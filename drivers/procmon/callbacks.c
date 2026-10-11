/*
 * Sentinel AV — process/thread/image/registry callbacks.  [Phase 2]
 *
 * Registers the small set of kernel callbacks that feed the real-time event
 * stream into the behavioral engine:
 *   - PsSetCreateProcessNotifyRoutineEx : every new process, with veto power
 *   - PsSetCreateThreadNotifyRoutine    : every new thread, incl. REMOTE threads
 *                                         created inside another process (the
 *                                         signature of injection/hollowing)
 *   - PsSetLoadImageNotifyRoutine       : every DLL/driver mapped into memory
 *                                         (side-loaded DLLs, unsigned drivers)
 *   - CmRegisterCallbackEx              : registry writes (Run keys, services,
 *                                         boot entries) — persistence, flagged
 *                                         and deniable in real time
 *
 * Together these turn a stream of individually-innocent actions into the
 * sequence the behavioral engine judges. Object callbacks for self-protection
 * live in selfprotect.c.
 *
 * Built with the WDK; kernel-mode C. Test only in the disposable VM.
 */
#include <ntddk.h>
#include "../common/comms.h"
#include "../common/shared_defs.h"

/* Globals owned by this translation unit (procmon's main unit). selfprotect.c
 * references gProcComms via extern. */
SENTINEL_COMMS gProcComms = {0};
BOOLEAN gBlockOnMaliciousProcess = TRUE;

/* Self-protection entry points implemented in selfprotect.c. */
NTSTATUS SentinelRegisterSelfProtection(VOID);
VOID SentinelUnregisterSelfProtection(VOID);
VOID SentinelRegisterProtectedPid(ULONG Pid);

LARGE_INTEGER gCookieCmCallback;
BOOLEAN gImageCallbackSet = FALSE;
BOOLEAN gThreadCallbackSet = FALSE;
BOOLEAN gCmCallbackSet = FALSE;

/* Copy a UNICODE_STRING image path into an event message (truncating safely). */
static VOID SentinelFillPath(_Out_ SENTINEL_EVENT_MSG *Evt,
                             _In_opt_ PCUNICODE_STRING Path) {
    ULONG chars = 0;
    if (Path != NULL && Path->Buffer != NULL) {
        chars = Path->Length / sizeof(WCHAR);
        if (chars >= SENTINEL_MAX_PATH) {
            chars = SENTINEL_MAX_PATH - 1;
        }
        RtlCopyMemory(Evt->path, Path->Buffer, chars * sizeof(WCHAR));
    }
    Evt->path[chars] = L'\0';
    Evt->path_chars = chars;
}

/* ----- Process creation (with veto) ------------------------------------- */
VOID SentinelCreateProcessNotify(_Inout_ PEPROCESS Process,
                                 _In_ HANDLE ProcessId,
                                 _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo) {
    SENTINEL_EVENT_MSG evt;
    UNREFERENCED_PARAMETER(Process);

    RtlZeroMemory(&evt, sizeof(evt));
    evt.target_process_id = (ULONG)(ULONG_PTR)ProcessId;

    if (CreateInfo != NULL) {
        /* Process start. */
        evt.parent_process_id = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;
        SentinelFillPath(&evt, CreateInfo->ImageFileName);

        /* Synchronously ask the engine; a strong malicious verdict can veto the
         * launch by setting CreationStatus to an error. */
        SENTINEL_MSG_HEADER header;
        SENTINEL_REPLY reply;
        RtlZeroMemory(&header, sizeof(header));
        header.version = SENTINEL_PROTOCOL_VERSION;
        header.kind = SentinelMsgProcessCreate;
        header.process_id = (ULONG)(ULONG_PTR)ProcessId;

        if (NT_SUCCESS(SentinelCommsAskVerdict(&gProcComms, &header, &evt,
                                               sizeof(evt), &reply, 2000)) &&
            gBlockOnMaliciousProcess &&
            (reply.action == SentinelActionBlock ||
             reply.action == SentinelActionKillRollback)) {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        }
    } else {
        /* Process exit. */
        SentinelCommsSendEvent(&gProcComms, SentinelMsgProcessExit, &evt,
                               sizeof(evt));
    }
}

/* ----- Thread creation (catches remote threads = injection) ------------- */
VOID SentinelCreateThreadNotify(_In_ HANDLE ProcessId,
                                _In_ HANDLE ThreadId,
                                _In_ BOOLEAN Create) {
    SENTINEL_EVENT_MSG evt;
    HANDLE currentPid = PsGetCurrentProcessId();

    if (!Create) {
        return;
    }
    RtlZeroMemory(&evt, sizeof(evt));
    evt.target_process_id = (ULONG)(ULONG_PTR)ProcessId;
    evt.parent_process_id = (ULONG)(ULONG_PTR)currentPid;
    evt.extra = (ULONG)(ULONG_PTR)ThreadId;

    /* If the creating process differs from the thread's owning process, this is
     * a REMOTE thread — the classic tail of the injection chain. Mark it so the
     * behavioral engine can raise the injection score (and procmon/shadowfs can
     * gate the target). */
    if (currentPid != ProcessId) {
        evt.extra |= 0x80000000u; /* remote-thread flag */
    }
    SentinelCommsSendEvent(&gProcComms, SentinelMsgThreadCreate, &evt,
                           sizeof(evt));
}

/* ----- Image load (side-loaded DLLs, unsigned drivers) ------------------ */
VOID SentinelLoadImageNotify(_In_opt_ PUNICODE_STRING FullImageName,
                             _In_ HANDLE ProcessId,
                             _In_ PIMAGE_INFO ImageInfo) {
    SENTINEL_EVENT_MSG evt;
    RtlZeroMemory(&evt, sizeof(evt));
    evt.target_process_id = (ULONG)(ULONG_PTR)ProcessId;
    /* SystemModeImage => a driver load; flag it for the rootkit/BYOVD path. */
    evt.extra = ImageInfo->SystemModeImage ? 1u : 0u;
    SentinelFillPath(&evt, FullImageName);
    SentinelCommsSendEvent(&gProcComms, SentinelMsgImageLoad, &evt, sizeof(evt));
}

/* ----- Registry (persistence) ------------------------------------------- */
NTSTATUS SentinelRegistryCallback(_In_ PVOID CallbackContext,
                                  _In_opt_ PVOID Argument1,
                                  _In_opt_ PVOID Argument2) {
    REG_NOTIFY_CLASS op;
    SENTINEL_EVENT_MSG evt;
    UNREFERENCED_PARAMETER(CallbackContext);

    if (Argument1 == NULL) {
        return STATUS_SUCCESS;
    }
    op = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    /* We care about value writes that establish persistence. */
    if (op == RegNtPreSetValueKey && Argument2 != NULL) {
        PREG_SET_VALUE_KEY_INFORMATION info =
            (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        RtlZeroMemory(&evt, sizeof(evt));
        evt.target_process_id = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        if (info->ValueName != NULL) {
            SentinelFillPath(&evt, info->ValueName);
        }
        SentinelCommsSendEvent(&gProcComms, SentinelMsgRegistryOp, &evt,
                               sizeof(evt));
        /* The engine can later request a deny; by default we observe, because a
         * synchronous registry deny on every write is too costly. Boot-critical
         * persistence keys are the exception and handled by policy. */
    }
    return STATUS_SUCCESS;
}

/* ----- Registration helpers called from DriverEntry --------------------- */
NTSTATUS SentinelRegisterProcessCallbacks(_In_ PDRIVER_OBJECT DriverObject) {
    NTSTATUS status;
    UNICODE_STRING altitude;

    status = PsSetCreateProcessNotifyRoutineEx(SentinelCreateProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = PsSetCreateThreadNotifyRoutine(SentinelCreateThreadNotify);
    if (NT_SUCCESS(status)) {
        gThreadCallbackSet = TRUE;
    }

    status = PsSetLoadImageNotifyRoutine(SentinelLoadImageNotify);
    if (NT_SUCCESS(status)) {
        gImageCallbackSet = TRUE;
    }

    RtlInitUnicodeString(&altitude, L"320800");
    status = CmRegisterCallbackEx(SentinelRegistryCallback, &altitude,
                                  DriverObject, NULL, &gCookieCmCallback, NULL);
    if (NT_SUCCESS(status)) {
        gCmCallbackSet = TRUE;
    }
    return STATUS_SUCCESS;
}

VOID SentinelUnregisterProcessCallbacks(VOID) {
    PsSetCreateProcessNotifyRoutineEx(SentinelCreateProcessNotify, TRUE);
    if (gThreadCallbackSet) {
        PsRemoveCreateThreadNotifyRoutine(SentinelCreateThreadNotify);
        gThreadCallbackSet = FALSE;
    }
    if (gImageCallbackSet) {
        PsRemoveLoadImageNotifyRoutine(SentinelLoadImageNotify);
        gImageCallbackSet = FALSE;
    }
    if (gCmCallbackSet) {
        CmUnRegisterCallback(gCookieCmCallback);
        gCmCallbackSet = FALSE;
    }
}

/* ----- Driver lifetime -------------------------------------------------- */
VOID SentinelProcmonUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    SentinelUnregisterProcessCallbacks();
    SentinelUnregisterSelfProtection();
    SentinelCommsClosePort(&gProcComms);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = SentinelProcmonUnload;

    /* procmon is a legacy (non-FltMgr) driver, so it uses the generic filter
     * communication only after the minifilter has created the shared filter.
     * Here it registers its callbacks and the object-callback self-protection. */
    status = SentinelRegisterProcessCallbacks(DriverObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SentinelRegisterSelfProtection();
    if (!NT_SUCCESS(status)) {
        SentinelUnregisterProcessCallbacks();
        return status;
    }

    /* Protect our own driver process context implicitly; the service registers
     * the user-mode service + watchdog PIDs over the comms port at startup. */
    SentinelRegisterProtectedPid((ULONG)(ULONG_PTR)PsGetCurrentProcessId());
    return STATUS_SUCCESS;
}
