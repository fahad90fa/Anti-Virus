/*
 * Sentinel AV — object-callback self-protection (anti-tamper).  [Phase 2]
 *
 * Malware's first move is often to disable the antivirus, so the engine defends
 * itself first. ObRegisterCallbacks intercepts attempts to open a handle to a
 * protected process or thread (the engine service and its helpers). Used
 * defensively, it strips the dangerous access rights (terminate, write memory,
 * create remote thread) from any non-trusted opener — stopping malware from
 * acquiring the access it needs to kill the antivirus or tamper with it.
 *
 * This complements the PPL protection level the service runs at and the mutual
 * watchdog (driver watches service, service watches driver).
 *
 * Built with the WDK; kernel-mode C.
 */
/* ntifs.h (NOT ntddk.h) is the single base header for this TU: it declares the
 * Ob callback types (POB_PRE_OPERATION_INFORMATION etc.) and PsProcessType/
 * PsThreadType. This TU never includes comms.h or sensor_comms.h, so there is no
 * ntddk vs ntifs ordering collision. */
#include <ntifs.h>
#include "../common/shared_defs.h"

/* Process/thread access-right bits. The kernel-mode headers on this WDK do not
 * expose these winnt.h constants to a km translation unit, so define them from
 * their well-known fixed values (guarded, so a header that does define them wins
 * with no redefinition). These are the DesiredAccess bits an opener requests. */
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE         0x0001u
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD     0x0002u
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION      0x0008u
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE          0x0020u
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION   0x0200u
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME    0x0800u
#endif
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE          0x0001u
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME     0x0002u
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT        0x0010u
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION    0x0020u
#endif

/* PIDs of the protected Sentinel processes (service + watchdog). The engine
 * registers them at startup via IOCTL_SENTINEL_REGISTER_PID, which the dispatch
 * routine turns into SentinelRegisterProtectedPid calls. Small fixed set. */
#define SENTINEL_MAX_PROTECTED 8
ULONG gProtectedPids[SENTINEL_MAX_PROTECTED] = {0};
/* volatile: read lock-free by the Ob pre-op, bumped by an atomic CAS slot-claim in
 * SentinelRegisterProtectedPid so concurrent writers stay bounded and race-free. */
volatile ULONG gProtectedCount = 0;
PVOID gObRegHandle = NULL;

/* Access rights we refuse to hand to untrusted openers of a protected process. */
#define SENTINEL_DANGEROUS_PROCESS_ACCESS \
    (PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | \
     PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION)

#define SENTINEL_DANGEROUS_THREAD_ACCESS \
    (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | \
     THREAD_SET_INFORMATION)

static BOOLEAN SentinelIsProtectedPid(ULONG Pid) {
    ULONG i;
    ULONG count = gProtectedCount;
    /* Defensive clamp: the count is strictly bounded by the CAS in
     * SentinelRegisterProtectedPid, but never read past the array. */
    if (count > SENTINEL_MAX_PROTECTED) {
        count = SENTINEL_MAX_PROTECTED;
    }
    for (i = 0; i < count; ++i) {
        if (gProtectedPids[i] == Pid) {
            return TRUE;
        }
    }
    return FALSE;
}

VOID SentinelRegisterProtectedPid(ULONG Pid) {
    LONG idx;

    if (SentinelIsProtectedPid(Pid)) {
        return;
    }
    /* Two writers can race here: DriverEntry registers our own PID while an engine
     * IOCTL_SENTINEL_REGISTER_PID thread registers the service/watchdog PIDs. Claim
     * a unique slot atomically so a concurrent writer can neither lose an update nor
     * push the count past the array. The count is bumped before the slot is stored,
     * so a lock-free reader may briefly see the new count with the slot still zero
     * (reads as PID 0 => no match, benign) — never an out-of-bounds read. */
    for (;;) {
        LONG cur = (LONG)gProtectedCount;
        if (cur >= (LONG)SENTINEL_MAX_PROTECTED) {
            return; /* table full */
        }
        if (InterlockedCompareExchange((volatile LONG *)&gProtectedCount,
                                       cur + 1, cur) == cur) {
            idx = cur;
            break;
        }
    }
    gProtectedPids[idx] = Pid;
    KeMemoryBarrier();
}

/* Pre-operation callback: strip dangerous rights unless the caller is itself a
 * protected/trusted Sentinel process or the kernel. */
OB_PREOP_CALLBACK_STATUS SentinelPreOpCallback(_In_ PVOID RegistrationContext,
                                               _In_ POB_PRE_OPERATION_INFORMATION Info) {
    ULONG targetPid = 0;
    ULONG callerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (Info->KernelHandle) {
        return OB_PREOP_SUCCESS; /* trust kernel-initiated handles */
    }

    if (Info->ObjectType == *PsProcessType) {
        PEPROCESS proc = (PEPROCESS)Info->Object;
        targetPid = (ULONG)(ULONG_PTR)PsGetProcessId(proc);
        if (!SentinelIsProtectedPid(targetPid) || SentinelIsProtectedPid(callerPid)) {
            return OB_PREOP_SUCCESS;
        }
        if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
            Info->Parameters->CreateHandleInformation.DesiredAccess &=
                ~SENTINEL_DANGEROUS_PROCESS_ACCESS;
        } else {
            Info->Parameters->DuplicateHandleInformation.DesiredAccess &=
                ~SENTINEL_DANGEROUS_PROCESS_ACCESS;
        }
    } else if (Info->ObjectType == *PsThreadType) {
        PETHREAD thread = (PETHREAD)Info->Object;
        targetPid = (ULONG)(ULONG_PTR)PsGetThreadProcessId(thread);
        if (!SentinelIsProtectedPid(targetPid) || SentinelIsProtectedPid(callerPid)) {
            return OB_PREOP_SUCCESS;
        }
        if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
            Info->Parameters->CreateHandleInformation.DesiredAccess &=
                ~SENTINEL_DANGEROUS_THREAD_ACCESS;
        } else {
            Info->Parameters->DuplicateHandleInformation.DesiredAccess &=
                ~SENTINEL_DANGEROUS_THREAD_ACCESS;
        }
    }
    return OB_PREOP_SUCCESS;
}

NTSTATUS SentinelRegisterSelfProtection(VOID) {
    OB_OPERATION_REGISTRATION ops[2];
    OB_CALLBACK_REGISTRATION reg;
    UNICODE_STRING altitude;

    RtlZeroMemory(ops, sizeof(ops));
    ops[0].ObjectType = PsProcessType;
    ops[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[0].PreOperation = SentinelPreOpCallback;
    ops[1].ObjectType = PsThreadType;
    ops[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[1].PreOperation = SentinelPreOpCallback;

    RtlInitUnicodeString(&altitude, L"320800");
    RtlZeroMemory(&reg, sizeof(reg));
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 2;
    reg.Altitude = altitude;
    reg.RegistrationContext = NULL;
    reg.OperationRegistration = ops;

    return ObRegisterCallbacks(&reg, &gObRegHandle);
}

VOID SentinelUnregisterSelfProtection(VOID) {
    if (gObRegHandle != NULL) {
        ObUnRegisterCallbacks(gObRegHandle);
        gObRegHandle = NULL;
    }
}
