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
 * PROCESS_*/THREAD_* access-right macros used below, and the Ob callback types.
 * This TU never includes comms.h/sensor_comms.h, so there is no ntddk/ntifs
 * ordering collision. */
#include <ntifs.h>
#include "../common/shared_defs.h"

/* PIDs of the protected Sentinel processes (service + watchdog). The engine
 * registers them at startup via IOCTL_SENTINEL_REGISTER_PID, which the dispatch
 * routine turns into SentinelRegisterProtectedPid calls. Small fixed set. */
#define SENTINEL_MAX_PROTECTED 8
ULONG gProtectedPids[SENTINEL_MAX_PROTECTED] = {0};
/* volatile + publish-slot-before-count so a lock-free reader (the Ob pre-op) that
 * observes an incremented count always sees the PID already stored. */
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
    for (i = 0; i < gProtectedCount; ++i) {
        if (gProtectedPids[i] == Pid) {
            return TRUE;
        }
    }
    return FALSE;
}

VOID SentinelRegisterProtectedPid(ULONG Pid) {
    if (gProtectedCount < SENTINEL_MAX_PROTECTED && !SentinelIsProtectedPid(Pid)) {
        /* Publish the slot before bumping the count so a concurrent lock-free
         * reader that sees the new count always sees the stored PID. */
        gProtectedPids[gProtectedCount] = Pid;
        KeMemoryBarrier();
        gProtectedCount++;
    }
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
