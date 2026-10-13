/*
 * Sentinel AV — sensor-driver control-device comms (implementation).
 *
 * See sensor_comms.h for the design. This module is FltMgr-free: it depends only
 * on ntddk.h + wdmsec.h and gives procmon/netfilter an inverted-call IOCTL
 * transport over a secured control device.
 *
 * IRQL / locking (summary; see the header):
 *   - Start/Stop/dispatch run at PASSIVE_LEVEL.
 *   - SendEvent / PostEntry / Drain / the CSQ callbacks are safe at <= DISPATCH
 *     (netfilter's WFP classify can be DISPATCH): spinlocks only, no paged pool,
 *     no waits.
 *   - AskVerdict waits, so it is PASSIVE_LEVEL only.
 *   - Three spinlocks (RingLock, the CSQ's CsqLock, WaiterLock) are NEVER held
 *     nested. Drain releases RingLock before any IoCsq* call.
 *   - KeSetEvent is only ever called with Wait=FALSE (legal while holding a
 *     spinlock at DISPATCH).
 *   - Nothing here is pageable (no alloc_text PAGE).
 *
 * Built with the WDK; kernel-mode C.
 */
#include <ntddk.h>
#include <wdmsec.h>
#include <initguid.h>
#include "shared_defs.h"
#include "sensor_comms.h"

/* Device-class GUID for the control device. initguid.h above makes DEFINE_GUID
 * emit this as inline data, so procmon needs no uuid.lib. */
DEFINE_GUID(GUID_SENTINEL_SENSOR_CLASS,
    0xe9a1c7d2, 0x0002, 0x4c3a, 0x9b, 0x11, 0x53, 0x45, 0x4e, 0x53, 0x4e, 0x52);

static PSENTINEL_SENSOR_COMMS SentinelpRecoverComms(_In_ PDEVICE_OBJECT DeviceObject) {
    return *(PSENTINEL_SENSOR_COMMS *)DeviceObject->DeviceExtension;
}

/* ---- Cancel-safe queue callbacks (classic IoCsqInitialize) --------------- */

static IO_CSQ_INSERT_IRP SentinelCsqInsertIrp;
static IO_CSQ_REMOVE_IRP SentinelCsqRemoveIrp;
static IO_CSQ_PEEK_NEXT_IRP SentinelCsqPeekNextIrp;
static IO_CSQ_ACQUIRE_LOCK SentinelCsqAcquireLock;
static IO_CSQ_RELEASE_LOCK SentinelCsqReleaseLock;
static IO_CSQ_COMPLETE_CANCELED_IRP SentinelCsqCompleteCanceledIrp;

static VOID SentinelCsqInsertIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp) {
    PSENTINEL_SENSOR_COMMS c = CONTAINING_RECORD(Csq, SENTINEL_SENSOR_COMMS, Csq);
    InsertTailList(&c->CsqList, &Irp->Tail.Overlay.ListEntry);
}

static VOID SentinelCsqRemoveIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(Csq);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

static PIRP SentinelCsqPeekNextIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp, _In_ PVOID PeekContext) {
    PSENTINEL_SENSOR_COMMS c = CONTAINING_RECORD(Csq, SENTINEL_SENSOR_COMMS, Csq);
    PLIST_ENTRY next;
    UNREFERENCED_PARAMETER(PeekContext);

    if (Irp == NULL) {
        next = c->CsqList.Flink;
    } else {
        next = Irp->Tail.Overlay.ListEntry.Flink;
    }
    if (next == &c->CsqList) {
        return NULL;
    }
    return CONTAINING_RECORD(next, IRP, Tail.Overlay.ListEntry);
}

static VOID SentinelCsqAcquireLock(_In_ PIO_CSQ Csq, _Out_ PKIRQL Irql) {
    PSENTINEL_SENSOR_COMMS c = CONTAINING_RECORD(Csq, SENTINEL_SENSOR_COMMS, Csq);
    KeAcquireSpinLock(&c->CsqLock, Irql);
}

static VOID SentinelCsqReleaseLock(_In_ PIO_CSQ Csq, _In_ KIRQL Irql) {
    PSENTINEL_SENSOR_COMMS c = CONTAINING_RECORD(Csq, SENTINEL_SENSOR_COMMS, Csq);
    KeReleaseSpinLock(&c->CsqLock, Irql);
}

static VOID SentinelCsqCompleteCanceledIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(Csq);
    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

/* ---- Event ring + inverted-call delivery --------------------------------- */

/* Pair buffered ring entries with pended GET_EVENT IRPs, oldest first. Never
 * holds RingLock across an IoCsq* call (which takes CsqLock). Safe <= DISPATCH. */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID SentinelpDrain(_In_ PSENTINEL_SENSOR_COMMS c) {
    for (;;) {
        KIRQL irql;
        PIRP irp;
        PIO_STACK_LOCATION sp;
        ULONG out;

        KeAcquireSpinLock(&c->RingLock, &irql);
        if (c->RingCount == 0) {
            KeReleaseSpinLock(&c->RingLock, irql);
            break;
        }
        KeReleaseSpinLock(&c->RingLock, irql);

        irp = IoCsqRemoveNextIrp(&c->Csq, NULL);
        if (irp == NULL) {
            break; /* events buffered but no reader is waiting */
        }

        KeAcquireSpinLock(&c->RingLock, &irql);
        if (c->RingCount == 0) {
            /* A concurrent drain emptied the ring; hand the IRP back and re-evaluate
             * (continue, not break): an event posted during this window must still be
             * paired with this now-re-inserted reader, or a sync-verdict event could
             * be stranded and silently fail-open. This cannot spin — the top-of-loop
             * empty check and a NULL IoCsqRemoveNextIrp both break, and each paired
             * entry decrements RingCount, so every iteration makes progress or exits. */
            KeReleaseSpinLock(&c->RingLock, irql);
            IoCsqInsertIrp(&c->Csq, irp, NULL);
            continue;
        }
        sp = IoGetCurrentIrpStackLocation(irp);
        out = sp->Parameters.DeviceIoControl.OutputBufferLength;
        {
            PSENTINEL_RING_ENTRY re = &c->Ring[c->RingHead];
            if (out >= re->Length) {
                RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, re->Buffer, re->Length);
                irp->IoStatus.Information = re->Length;
                irp->IoStatus.Status = STATUS_SUCCESS;
            } else {
                irp->IoStatus.Information = 0;
                irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            }
            c->RingHead = (c->RingHead + 1) % c->RingCapacity;
            c->RingCount--;
        }
        KeReleaseSpinLock(&c->RingLock, irql);

        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }
}

/* Buffer one event (drop-oldest when full, counted) then drain. Safe <= DISPATCH. */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID SentinelpPostEntry(_In_ PSENTINEL_SENSOR_COMMS c,
                               _In_ const SENTINEL_RING_ENTRY *Entry) {
    KIRQL irql;
    BOOLEAN dropped = FALSE;

    KeAcquireSpinLock(&c->RingLock, &irql);
    if (c->RingCount == c->RingCapacity) {
        c->RingHead = (c->RingHead + 1) % c->RingCapacity;
        c->RingCount--;
        dropped = TRUE;
    }
    c->Ring[c->RingTail] = *Entry;
    c->RingTail = (c->RingTail + 1) % c->RingCapacity;
    c->RingCount++;
    KeReleaseSpinLock(&c->RingLock, irql);

    if (dropped) {
        LONG64 total = InterlockedIncrement64(&c->Dropped);
        if ((total & 0xFF) == 1) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "Sentinel: sensor event ring full (cap=%lu), total dropped=%I64d\n",
                       c->RingCapacity, total);
        }
    }

    SentinelpDrain(c);
}

/* ---- Public producer API ------------------------------------------------- */

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS SentinelSensorSendEvent(_In_ PSENTINEL_SENSOR_COMMS Comms,
                                 _In_ SENTINEL_MSG_KIND Kind,
                                 _In_reads_bytes_opt_(PayloadBytes) PVOID Payload,
                                 _In_ ULONG PayloadBytes) {
    SENTINEL_RING_ENTRY entry;
    SENTINEL_MSG_HEADER *h;

    if (Comms == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Comms->State != SENTINEL_SENSOR_STATE_RUNNING || !Comms->EngineConnected) {
        return STATUS_PORT_DISCONNECTED; /* mirrors comms.c: drop when no engine */
    }
    if (sizeof(SENTINEL_MSG_HEADER) + PayloadBytes > SENTINEL_SENSOR_EVENT_MAX) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&entry, sizeof(entry));
    h = (SENTINEL_MSG_HEADER *)entry.Buffer;
    h->version = SENTINEL_PROTOCOL_VERSION;
    h->kind = (uint32_t)Kind;
    h->sequence = (uint64_t)InterlockedIncrement64(&Comms->Sequence);
    h->payload_bytes = PayloadBytes;
    h->reserved = 0;
    if (Payload != NULL && PayloadBytes > 0) {
        RtlCopyMemory(entry.Buffer + sizeof(SENTINEL_MSG_HEADER), Payload, PayloadBytes);
    }
    entry.Length = (ULONG)sizeof(SENTINEL_MSG_HEADER) + PayloadBytes;

    SentinelpPostEntry(Comms, &entry);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SentinelSensorAskVerdict(_In_ PSENTINEL_SENSOR_COMMS Comms,
                                  _Inout_ SENTINEL_MSG_HEADER *Header,
                                  _In_reads_bytes_opt_(PayloadBytes) PVOID Payload,
                                  _In_ ULONG PayloadBytes,
                                  _Out_ SENTINEL_REPLY *Reply,
                                  _In_ LONGLONG TimeoutMs) {
    KIRQL irql;
    ULONG i;
    LONG idx;
    uint64_t seq;
    PSENTINEL_VERDICT_WAITER w;
    SENTINEL_RING_ENTRY entry;
    SENTINEL_MSG_HEADER *h;
    LARGE_INTEGER timeout;
    NTSTATUS status;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Comms == NULL || Header == NULL || Reply == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Reply, sizeof(*Reply));
    Reply->sequence = Header->sequence;
    Reply->risk = SentinelRiskUnknown;
    Reply->action = Comms->FailClosed ? SentinelActionBlock : SentinelActionAllow;

    if (!Comms->SupportsSyncVerdict) {
        return STATUS_NOT_SUPPORTED;
    }
    if (Comms->State != SENTINEL_SENSOR_STATE_RUNNING || !Comms->EngineConnected) {
        return STATUS_PORT_DISCONNECTED; /* fail-open/closed reply already filled */
    }
    if (sizeof(SENTINEL_MSG_HEADER) + PayloadBytes > SENTINEL_SENSOR_EVENT_MAX) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Claim a verdict slot. */
    idx = -1;
    KeAcquireSpinLock(&Comms->WaiterLock, &irql);
    for (i = 0; i < SENTINEL_SENSOR_MAX_VERDICTS; ++i) {
        if (!Comms->Waiters[i].InUse) {
            idx = (LONG)i;
            break;
        }
    }
    if (idx < 0) {
        KeReleaseSpinLock(&Comms->WaiterLock, irql);
        return STATUS_INSUFFICIENT_RESOURCES; /* fail-safe reply already filled */
    }
    seq = (uint64_t)InterlockedIncrement64(&Comms->Sequence);
    w = &Comms->Waiters[idx];
    w->InUse = 1;
    w->Answered = FALSE;
    w->Sequence = seq;
    KeInitializeEvent(&w->Done, NotificationEvent, FALSE);
    KeReleaseSpinLock(&Comms->WaiterLock, irql);

    /* Build + deliver the event tagged as requiring a verdict. */
    RtlZeroMemory(&entry, sizeof(entry));
    h = (SENTINEL_MSG_HEADER *)entry.Buffer;
    *h = *Header;
    h->version = SENTINEL_PROTOCOL_VERSION;
    h->sequence = seq;
    h->payload_bytes = PayloadBytes;
    h->reserved |= SENTINEL_FLAG_SYNC_VERDICT;
    Header->sequence = seq;
    if (Payload != NULL && PayloadBytes > 0) {
        RtlCopyMemory(entry.Buffer + sizeof(SENTINEL_MSG_HEADER), Payload, PayloadBytes);
    }
    entry.Length = (ULONG)sizeof(SENTINEL_MSG_HEADER) + PayloadBytes;
    SentinelpPostEntry(Comms, &entry);

    /* Wait (bounded) for the engine's POST_VERDICT. */
    timeout.QuadPart = -(10000LL * (LONGLONG)TimeoutMs);
    (VOID)KeWaitForSingleObject(&w->Done, Executive, KernelMode, FALSE, &timeout);

    KeAcquireSpinLock(&Comms->WaiterLock, &irql);
    if (w->Answered) {
        *Reply = w->Reply;
        status = STATUS_SUCCESS;
    } else {
        /* timeout: fill fail-open/closed */
        RtlZeroMemory(Reply, sizeof(*Reply));
        Reply->sequence = seq;
        Reply->risk = SentinelRiskUnknown;
        Reply->action = Comms->FailClosed ? SentinelActionBlock : SentinelActionAllow;
        status = STATUS_TIMEOUT;
    }
    w->InUse = 0;
    KeReleaseSpinLock(&Comms->WaiterLock, irql);
    return status;
}

/* ---- IRP dispatch -------------------------------------------------------- */

static VOID SentinelpWakeAllWaiters(_In_ PSENTINEL_SENSOR_COMMS c) {
    KIRQL irql;
    ULONG i;
    KeAcquireSpinLock(&c->WaiterLock, &irql);
    for (i = 0; i < SENTINEL_SENSOR_MAX_VERDICTS; ++i) {
        if (c->Waiters[i].InUse && !c->Waiters[i].Answered) {
            RtlZeroMemory(&c->Waiters[i].Reply, sizeof(c->Waiters[i].Reply));
            c->Waiters[i].Reply.sequence = c->Waiters[i].Sequence;
            c->Waiters[i].Reply.risk = SentinelRiskUnknown;
            c->Waiters[i].Reply.action =
                c->FailClosed ? SentinelActionBlock : SentinelActionAllow;
            c->Waiters[i].Answered = TRUE;
            KeSetEvent(&c->Waiters[i].Done, IO_NO_INCREMENT, FALSE);
        }
    }
    KeReleaseSpinLock(&c->WaiterLock, irql);
}

static VOID SentinelpCancelAllPended(_In_ PSENTINEL_SENSOR_COMMS c) {
    for (;;) {
        PIRP p = IoCsqRemoveNextIrp(&c->Csq, NULL);
        if (p == NULL) {
            break;
        }
        p->IoStatus.Status = STATUS_CANCELLED;
        p->IoStatus.Information = 0;
        IoCompleteRequest(p, IO_NO_INCREMENT);
    }
}

NTSTATUS SentinelSensorDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    PSENTINEL_SENSOR_COMMS c = SentinelpRecoverComms(DeviceObject);
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    switch (sp->MajorFunction) {
    case IRP_MJ_CREATE: {
        LONG was = InterlockedCompareExchange(&c->HasClient, 1, 0);
        if (was != 0) {
            status = STATUS_DEVICE_ALREADY_ATTACHED;
        } else {
            c->OwnerFileObject = sp->FileObject;
            InterlockedExchange(&c->EngineConnected, 0);
            status = STATUS_SUCCESS;
        }
        break;
    }

    case IRP_MJ_CLOSE:
        status = STATUS_SUCCESS;
        break;

    case IRP_MJ_CLEANUP:
        if (sp->FileObject == c->OwnerFileObject) {
            KIRQL irql;
            InterlockedExchange(&c->EngineConnected, 0);
            SentinelpCancelAllPended(c);
            KeAcquireSpinLock(&c->RingLock, &irql);
            c->RingHead = 0;
            c->RingTail = 0;
            c->RingCount = 0;
            KeReleaseSpinLock(&c->RingLock, irql);
            SentinelpWakeAllWaiters(c);
            c->OwnerFileObject = NULL;
            InterlockedExchange(&c->HasClient, 0);
        }
        status = STATUS_SUCCESS;
        break;

    case IRP_MJ_DEVICE_CONTROL: {
        ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;
        ULONG inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;
        PVOID buf = Irp->AssociatedIrp.SystemBuffer;

        /* Every privileged IOCTL requires the owning engine handle + connection,
         * except CONNECT (which establishes the connection). */
        if (code == IOCTL_SENTINEL_CONNECT) {
            SENTINEL_CONNECT_CONTEXT *cc;
            if (sp->FileObject != c->OwnerFileObject) {
                status = STATUS_INVALID_DEVICE_STATE;
                break;
            }
            if (inLen < sizeof(SENTINEL_CONNECT_CONTEXT) ||
                outLen < sizeof(SENTINEL_CONNECT_CONTEXT) || buf == NULL) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            cc = (SENTINEL_CONNECT_CONTEXT *)buf;
            if (cc->version != SENTINEL_PROTOCOL_VERSION) {
                status = STATUS_REVISION_MISMATCH;
                break;
            }
            InterlockedExchange(&c->EngineConnected, 1);
            cc->version = SENTINEL_PROTOCOL_VERSION;
            cc->reserved = 0;
            info = sizeof(SENTINEL_CONNECT_CONTEXT);
            status = STATUS_SUCCESS;
            break;
        }

        if (sp->FileObject != c->OwnerFileObject || !c->EngineConnected) {
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }

        switch (code) {
        case IOCTL_SENTINEL_GET_EVENT:
            if (outLen < SENTINEL_SENSOR_EVENT_MAX) {
                info = SENTINEL_SENSOR_EVENT_MAX;
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            /* IoCsqInsertIrp marks the IRP pending internally; do NOT complete it
             * here. The drain pairs it with any buffered event. */
            IoCsqInsertIrp(&c->Csq, Irp, NULL);
            SentinelpDrain(c);
            return STATUS_PENDING;

        case IOCTL_SENTINEL_POST_VERDICT: {
            SENTINEL_REPLY *r;
            KIRQL irql;
            ULONG i;
            if (inLen < sizeof(SENTINEL_REPLY) || buf == NULL) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            r = (SENTINEL_REPLY *)buf;
            KeAcquireSpinLock(&c->WaiterLock, &irql);
            for (i = 0; i < SENTINEL_SENSOR_MAX_VERDICTS; ++i) {
                if (c->Waiters[i].InUse && !c->Waiters[i].Answered &&
                    c->Waiters[i].Sequence == r->sequence) {
                    c->Waiters[i].Reply = *r;
                    c->Waiters[i].Answered = TRUE;
                    KeSetEvent(&c->Waiters[i].Done, IO_NO_INCREMENT, FALSE);
                    break;
                }
            }
            KeReleaseSpinLock(&c->WaiterLock, irql);
            status = STATUS_SUCCESS; /* an unmatched/late sequence is harmless */
            break;
        }

        case IOCTL_SENTINEL_REGISTER_PID: {
            SENTINEL_REGISTER_PID_REQUEST *rq;
            ULONG i;
            if (c->OnRegisterPid == NULL) {
                status = STATUS_NOT_SUPPORTED;
                break;
            }
            if (inLen < sizeof(SENTINEL_REGISTER_PID_REQUEST) || buf == NULL) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            rq = (SENTINEL_REGISTER_PID_REQUEST *)buf;
            if (rq->count > SENTINEL_MAX_REGISTER_PIDS) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            for (i = 0; i < rq->count; ++i) {
                if (rq->pids[i] != 0) {
                    c->OnRegisterPid(rq->pids[i]);
                }
            }
            status = STATUS_SUCCESS;
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ---- Lifetime ------------------------------------------------------------ */

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SentinelSensorCommsStart(_Inout_ PSENTINEL_SENSOR_COMMS Comms,
                                  _In_ PDRIVER_OBJECT DriverObject,
                                  _In_ const SENTINEL_SENSOR_CONFIG *Config) {
    DECLARE_CONST_UNICODE_STRING(sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    UNICODE_STRING deviceName;
    UNICODE_STRING linkName;
    NTSTATUS status;

    if (Comms == NULL || DriverObject == NULL || Config == NULL ||
        Config->DeviceName == NULL || Config->SymbolicLinkName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Comms, sizeof(*Comms));
    Comms->SupportsSyncVerdict = Config->SupportsSyncVerdict;
    Comms->FailClosed = Config->FailClosed;
    Comms->OnRegisterPid = Config->OnRegisterPid;
    KeInitializeSpinLock(&Comms->RingLock);
    KeInitializeSpinLock(&Comms->CsqLock);
    KeInitializeSpinLock(&Comms->WaiterLock);
    InitializeListHead(&Comms->CsqList);
    Comms->RingCapacity = SENTINEL_SENSOR_RING_CAPACITY;

    Comms->Ring = (PSENTINEL_RING_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        (SIZE_T)Comms->RingCapacity * sizeof(SENTINEL_RING_ENTRY),
        SENTINEL_SENSOR_POOL_TAG);
    if (Comms->Ring == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCsqInitialize(&Comms->Csq, SentinelCsqInsertIrp, SentinelCsqRemoveIrp,
                             SentinelCsqPeekNextIrp, SentinelCsqAcquireLock,
                             SentinelCsqReleaseLock, SentinelCsqCompleteCanceledIrp);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(Comms->Ring, SENTINEL_SENSOR_POOL_TAG);
        Comms->Ring = NULL;
        return status;
    }

    RtlInitUnicodeString(&deviceName, Config->DeviceName);
    status = IoCreateDeviceSecure(DriverObject, sizeof(PSENTINEL_SENSOR_COMMS),
                                  &deviceName, (DEVICE_TYPE)SENTINEL_FILE_DEVICE,
                                  FILE_DEVICE_SECURE_OPEN, FALSE, &sddl,
                                  &GUID_SENTINEL_SENSOR_CLASS, &Comms->DeviceObject);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(Comms->Ring, SENTINEL_SENSOR_POOL_TAG);
        Comms->Ring = NULL;
        return status;
    }
    *(PSENTINEL_SENSOR_COMMS *)Comms->DeviceObject->DeviceExtension = Comms;

    RtlInitUnicodeString(&linkName, Config->SymbolicLinkName);
    RtlInitUnicodeString(&Comms->SymlinkName, Config->SymbolicLinkName);
    status = IoCreateSymbolicLink(&linkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(Comms->DeviceObject);
        Comms->DeviceObject = NULL;
        ExFreePoolWithTag(Comms->Ring, SENTINEL_SENSOR_POOL_TAG);
        Comms->Ring = NULL;
        return status;
    }
    Comms->SymlinkCreated = TRUE;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = SentinelSensorDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = SentinelSensorDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SentinelSensorDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SentinelSensorDispatch;

    InterlockedExchange(&Comms->State, SENTINEL_SENSOR_STATE_RUNNING);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID SentinelSensorCommsStop(_Inout_ PSENTINEL_SENSOR_COMMS Comms) {
    if (Comms == NULL || Comms->DeviceObject == NULL) {
        return;
    }
    InterlockedExchange(&Comms->State, SENTINEL_SENSOR_STATE_STOPPING);

    /* The caller has already torn down every event producer, so nothing can post
     * after this point. Cancel any still-pended reader IRPs and wake any waiter. */
    SentinelpCancelAllPended(Comms);
    SentinelpWakeAllWaiters(Comms);

    if (Comms->SymlinkCreated) {
        IoDeleteSymbolicLink(&Comms->SymlinkName);
        Comms->SymlinkCreated = FALSE;
    }
    IoDeleteDevice(Comms->DeviceObject);
    Comms->DeviceObject = NULL;
    if (Comms->Ring != NULL) {
        ExFreePoolWithTag(Comms->Ring, SENTINEL_SENSOR_POOL_TAG);
        Comms->Ring = NULL;
    }
}
