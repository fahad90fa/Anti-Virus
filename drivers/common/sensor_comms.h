/*
 * Sentinel AV — sensor-driver control-device comms (declarations).
 *
 * The non-minifilter sensor drivers (procmon: process/thread/image/registry +
 * object-callback self-protection; netfilter: WFP callout) cannot use the FltMgr
 * communication port that comms.h/comms.c provide — they have no PFLT_FILTER.
 * This module gives them an equivalent transport built on a secured control
 * DEVICE_OBJECT and an INVERTED-CALL IOCTL model:
 *
 *   - The user-mode engine opens the device (CreateFile on \\.\Sentinel{Proc,Net}),
 *     sends IOCTL_SENTINEL_CONNECT to validate the protocol version, then keeps one
 *     or more IOCTL_SENTINEL_GET_EVENT IRPs outstanding. The driver PENDS those IRPs
 *     (cancel-safe, via IO_CSQ) and completes one whenever an event is produced; a
 *     bounded ring buffers events when no reader IRP is waiting (drop-oldest, counted).
 *   - For procmon's synchronous process-create veto, SentinelSensorAskVerdict delivers
 *     the event tagged SENTINEL_FLAG_SYNC_VERDICT and blocks (bounded timeout) until the
 *     engine returns IOCTL_SENTINEL_POST_VERDICT with the matching sequence. It fails
 *     OPEN (allow) on timeout/disconnect unless the driver is configured fail-closed.
 *   - IOCTL_SENTINEL_REGISTER_PID lets the engine register protected PIDs for
 *     self-protection.
 *
 * The wire MESSAGE structs are the shared ones in shared_defs.h (unchanged).
 *
 * This header is kernel-only but intentionally includes ONLY "shared_defs.h": it must
 * NOT pull in <ntddk.h> or <ntifs.h>, so the INCLUDING translation unit controls which
 * single base header it uses (mixing ntddk.h and ntifs.h in one TU is what caused the
 * original PEPROCESS/PETHREAD C2371 redefinition). Include your base header first, then
 * this. Built with the WDK; kernel-mode C.
 */
#ifndef SENTINEL_DRIVERS_SENSOR_COMMS_H
#define SENTINEL_DRIVERS_SENSOR_COMMS_H

#include "shared_defs.h"

#define SENTINEL_SENSOR_POOL_TAG      'cneS'  /* "Senc" */
#define SENTINEL_SENSOR_RING_CAPACITY 256u
#define SENTINEL_SENSOR_MAX_VERDICTS  64u
#define SENTINEL_SENSOR_EVENT_MAX \
    (sizeof(SENTINEL_MSG_HEADER) + sizeof(SENTINEL_EVENT_MSG))

#define SENTINEL_SENSOR_STATE_STOPPED  0L
#define SENTINEL_SENSOR_STATE_RUNNING  1L
#define SENTINEL_SENSOR_STATE_STOPPING 2L

/* One buffered event: Length = sizeof(header) + payload_bytes, Buffer holds the
 * SENTINEL_MSG_HEADER immediately followed by the payload. */
typedef struct _SENTINEL_RING_ENTRY {
    ULONG Length;
    UCHAR Buffer[SENTINEL_SENSOR_EVENT_MAX];
} SENTINEL_RING_ENTRY, *PSENTINEL_RING_ENTRY;

/* One outstanding synchronous-verdict waiter. Lives in a fixed array for the
 * driver-image lifetime, so there is no per-wait allocation and no KEVENT UAF. */
typedef struct _SENTINEL_VERDICT_WAITER {
    volatile LONG InUse;
    BOOLEAN Answered;
    uint64_t Sequence;
    KEVENT Done;
    SENTINEL_REPLY Reply;
} SENTINEL_VERDICT_WAITER, *PSENTINEL_VERDICT_WAITER;

/* Callback invoked (once per PID) when the engine sends IOCTL_SENTINEL_REGISTER_PID.
 * Its signature matches procmon's SentinelRegisterProtectedPid exactly. */
typedef VOID (*SENTINEL_REGISTER_PID_CALLBACK)(_In_ ULONG Pid);

/* Per-driver configuration passed to SentinelSensorCommsStart. */
typedef struct _SENTINEL_SENSOR_CONFIG {
    PCWSTR DeviceName;                        /* e.g. SENTINEL_PROC_DEVICE_NAME */
    PCWSTR SymbolicLinkName;                  /* e.g. SENTINEL_PROC_SYMLINK_NAME */
    BOOLEAN SupportsSyncVerdict;              /* TRUE for procmon, FALSE for netfilter */
    BOOLEAN FailClosed;                       /* FALSE = fail-open (default) */
    SENTINEL_REGISTER_PID_CALLBACK OnRegisterPid; /* NULL if unsupported */
} SENTINEL_SENSOR_CONFIG, *PSENTINEL_SENSOR_CONFIG;

/* Per-driver comms state. Declared as a zero-initialized global by each driver.
 * The struct is public (not opaque) so netfilter can read DeviceObject to anchor
 * its WFP callout on the same secured device. */
typedef struct _SENTINEL_SENSOR_COMMS {
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING SymlinkName;
    BOOLEAN SymlinkCreated;
    BOOLEAN SupportsSyncVerdict;
    BOOLEAN FailClosed;
    volatile LONG State;                      /* SENTINEL_SENSOR_STATE_* */
    volatile LONG HasClient;                  /* single-client claim (IRP_MJ_CREATE) */
    PFILE_OBJECT OwnerFileObject;             /* the one engine handle */
    volatile LONG EngineConnected;            /* set by IOCTL_SENTINEL_CONNECT */
    volatile LONG64 Sequence;                 /* monotonic message/verdict sequence */

    KSPIN_LOCK RingLock;
    PSENTINEL_RING_ENTRY Ring;
    ULONG RingCapacity;
    ULONG RingHead;
    ULONG RingTail;
    ULONG RingCount;
    volatile LONG64 Dropped;

    IO_CSQ Csq;                               /* cancel-safe queue of GET_EVENT IRPs */
    KSPIN_LOCK CsqLock;
    LIST_ENTRY CsqList;

    KSPIN_LOCK WaiterLock;
    SENTINEL_VERDICT_WAITER Waiters[SENTINEL_SENSOR_MAX_VERDICTS];

    SENTINEL_REGISTER_PID_CALLBACK OnRegisterPid;
} SENTINEL_SENSOR_COMMS, *PSENTINEL_SENSOR_COMMS;

/* Create the secured control device + symlink, install IRP dispatch, and start
 * accepting a client. PASSIVE_LEVEL (DriverEntry). On failure nothing leaks. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SentinelSensorCommsStart(_Inout_ PSENTINEL_SENSOR_COMMS Comms,
                                  _In_ PDRIVER_OBJECT DriverObject,
                                  _In_ const SENTINEL_SENSOR_CONFIG *Config);

/* Wake all waiters fail-safe, cancel pended IRPs, delete symlink + device, free
 * the ring. The caller MUST have already torn down every event producer (callbacks
 * / WFP callouts) so no producer can touch the ring after this. PASSIVE_LEVEL. */
_IRQL_requires_(PASSIVE_LEVEL)
VOID SentinelSensorCommsStop(_Inout_ PSENTINEL_SENSOR_COMMS Comms);

/* Send an asynchronous event (no reply). Safe at IRQL <= DISPATCH_LEVEL (WFP
 * classify). Drops the event if the engine is not connected (mirrors comms.c). */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS SentinelSensorSendEvent(_In_ PSENTINEL_SENSOR_COMMS Comms,
                                 _In_ SENTINEL_MSG_KIND Kind,
                                 _In_reads_bytes_opt_(PayloadBytes) PVOID Payload,
                                 _In_ ULONG PayloadBytes);

/* Send a synchronous request and block for a verdict. PASSIVE_LEVEL only (it
 * waits). On timeout/disconnect/no-slot, Reply is filled fail-open (or fail-closed
 * if configured) so the caller never deadlocks. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SentinelSensorAskVerdict(_In_ PSENTINEL_SENSOR_COMMS Comms,
                                  _Inout_ SENTINEL_MSG_HEADER *Header,
                                  _In_reads_bytes_opt_(PayloadBytes) PVOID Payload,
                                  _In_ ULONG PayloadBytes,
                                  _Out_ SENTINEL_REPLY *Reply,
                                  _In_ LONGLONG TimeoutMs);

/* The single IRP dispatch routine (CREATE/CLEANUP/CLOSE/DEVICE_CONTROL). Declared
 * via the DRIVER_DISPATCH typedef so PREfast sees its function role. */
DRIVER_DISPATCH SentinelSensorDispatch;

#endif /* SENTINEL_DRIVERS_SENSOR_COMMS_H */
