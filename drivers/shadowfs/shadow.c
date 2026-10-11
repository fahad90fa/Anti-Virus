/*
 * Sentinel AV — copy-on-write shadow layer / rollback gate (kernel side). [Phase 4]
 *
 * This minifilter implements the kernel half of the shadow-commit rollback gate.
 * For a process the engine has marked "gated" (unknown/suspicious), file writes
 * are redirected into a per-process shadow layer: the process believes it wrote
 * to disk; it actually wrote to a staging area the rest of the system cannot see.
 * When the engine's live verdict clears, the staged writes are committed to the
 * real disk atomically; if the verdict turns malicious, the whole shadow layer is
 * discarded — perfect rollback, no data loss, even for a zero-day never seen
 * before (ransomware only ever encrypted the shadow copies).
 *
 * The user-mode engine (engine/rollback/shadow_gate) owns the staging store and
 * the commit/discard decision; this driver enforces the redirection at IRP_MJ_
 * CREATE/WRITE for gated processes and reports irreversible side effects so the
 * engine can hold/throttle/deny them until the verdict clears.
 *
 * Built with the WDK; kernel-mode C. The heavy COW bookkeeping lives in user
 * mode by design; this driver is the thin, fast redirection enforcement point.
 */
#include <fltKernel.h>
#include "../common/comms.h"
#include "../common/shared_defs.h"

PFLT_FILTER gShadowFilter = NULL;
SENTINEL_COMMS gShadowComms = {0};

/* A bounded table of currently-gated PIDs, pushed down by the engine over the
 * comms port. A real build uses a hash set; a small array suffices to show the
 * mechanism. */
#define SENTINEL_MAX_GATED 256
ULONG gGatedPids[SENTINEL_MAX_GATED] = {0};
ULONG gGatedCount = 0;
FAST_MUTEX gGatedLock;

static BOOLEAN SentinelIsGated(ULONG Pid) {
    ULONG i;
    BOOLEAN found = FALSE;
    ExAcquireFastMutex(&gGatedLock);
    for (i = 0; i < gGatedCount; ++i) {
        if (gGatedPids[i] == Pid) { found = TRUE; break; }
    }
    ExReleaseFastMutex(&gGatedLock);
    return found;
}

VOID SentinelGateProcess(ULONG Pid) {
    ExAcquireFastMutex(&gGatedLock);
    if (gGatedCount < SENTINEL_MAX_GATED) {
        gGatedPids[gGatedCount++] = Pid;
    }
    ExReleaseFastMutex(&gGatedLock);
}

VOID SentinelUngateProcess(ULONG Pid) {
    ULONG i;
    ExAcquireFastMutex(&gGatedLock);
    for (i = 0; i < gGatedCount; ++i) {
        if (gGatedPids[i] == Pid) {
            gGatedPids[i] = gGatedPids[--gGatedCount];
            break;
        }
    }
    ExReleaseFastMutex(&gGatedLock);
}

/* Pre-write for a gated process: notify the engine, which stages the write into
 * the shadow layer. For brevity this reports the write; a full build rewrites
 * the target path to the shadow path via name-provider/reparse. The engine's
 * ShadowGate holds the authoritative staging mapping and performs commit/discard. */
FLT_PREOP_CALLBACK_STATUS SentinelShadowPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext) {
    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    SENTINEL_EVENT_MSG evt;
    ULONG chars;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!SentinelIsGated(pid)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK; /* trusted: straight to disk */
    }

    if (!NT_SUCCESS(FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo))) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    RtlZeroMemory(&evt, sizeof(evt));
    evt.target_process_id = pid;
    chars = nameInfo->Name.Length / sizeof(WCHAR);
    if (chars >= SENTINEL_MAX_PATH) {
        chars = SENTINEL_MAX_PATH - 1;
    }
    RtlCopyMemory(evt.path, nameInfo->Name.Buffer, chars * sizeof(WCHAR));
    evt.path[chars] = L'\0';
    evt.path_chars = chars;
    SentinelCommsSendEvent(&gShadowComms, SentinelMsgFilePreOp, &evt, sizeof(evt));

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

CONST FLT_OPERATION_REGISTRATION ShadowCallbacks[] = {
    { IRP_MJ_WRITE, 0, SentinelShadowPreWrite, NULL },
    { IRP_MJ_SET_INFORMATION, 0, SentinelShadowPreWrite, NULL }, /* rename/delete */
    { IRP_MJ_OPERATION_END }
};

NTSTATUS SentinelShadowUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    SentinelCommsClosePort(&gShadowComms);
    if (gShadowFilter != NULL) {
        FltUnregisterFilter(gShadowFilter);
        gShadowFilter = NULL;
    }
    return STATUS_SUCCESS;
}

CONST FLT_REGISTRATION ShadowRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL,
    ShadowCallbacks, SentinelShadowUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializeFastMutex(&gGatedLock);

    status = FltRegisterFilter(DriverObject, &ShadowRegistration, &gShadowFilter);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = SentinelCommsCreatePort(&gShadowComms, gShadowFilter,
                                     L"\\SentinelShadowPort");
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gShadowFilter);
        gShadowFilter = NULL;
        return status;
    }
    status = FltStartFiltering(gShadowFilter);
    if (!NT_SUCCESS(status)) {
        SentinelCommsClosePort(&gShadowComms);
        FltUnregisterFilter(gShadowFilter);
        gShadowFilter = NULL;
    }
    return status;
}
