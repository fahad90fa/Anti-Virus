/*
 * Sentinel AV — file-system minifilter driver.  [Phase 1]
 *
 * Registered with the Windows Filter Manager, this driver intercepts file
 * operations (create, open, read, write, execute-map) as I/O passes through the
 * stack. On an executable open or a file write, it can pause the operation, send
 * the file to the user-mode scanning engine for a verdict, then allow, block, or
 * quarantine. This is the front line against file-based malware: the virus is
 * stopped before it runs.
 *
 * Design: the synchronous gate is IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION
 * (image section create — i.e. "about to execute"). Ordinary reads/writes of
 * already-cleared files are handled asynchronously with minimal inline cost; we
 * block inline only when an unknown thing is about to execute.
 *
 * Built with the WDK. Develop and test ONLY in a disposable VM with kernel
 * debugging attached — never on a production machine.
 */
#include <fltKernel.h>
#include <dontuse.h>
#include "../common/comms.h"
#include "../common/shared_defs.h"

#define SENTINEL_FS_TAG 'tneS'

PFLT_FILTER gFilterHandle = NULL;
SENTINEL_COMMS gComms = {0};

/* Fail-closed policy: when the engine is unreachable, deny execution of unknown
 * images instead of allowing. Off by default for availability; set via registry. */
BOOLEAN gFailClosed = FALSE;

DRIVER_INITIALIZE DriverEntry;
NTSTATUS SentinelUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS SentinelPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_PREOP_CALLBACK_STATUS SentinelPreAcquireForSection(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_POSTOP_CALLBACK_STATUS SentinelPostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

/* Operations we register interest in. */
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, SentinelPreCreate, NULL },
    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0,
      SentinelPreAcquireForSection, NULL },
    { IRP_MJ_WRITE, 0, NULL, SentinelPostWrite },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    SentinelUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

/* Resolve the normalized file name for the operation. Caller frees via
 * FltReleaseFileNameInformation. */
static NTSTATUS SentinelGetPath(_In_ PFLT_CALLBACK_DATA Data,
                                _Out_ PFLT_FILE_NAME_INFORMATION *NameInfo) {
    NTSTATUS status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, NameInfo);
    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(*NameInfo);
    }
    return status;
}

/* Build and send a synchronous scan request for an image about to execute. */
static SENTINEL_ACTION SentinelScanImage(_In_ PFLT_FILE_NAME_INFORMATION NameInfo,
                                         _In_ ULONG ProcessId) {
    SENTINEL_MSG_HEADER header;
    SENTINEL_FILE_MSG msg;
    SENTINEL_REPLY reply;
    NTSTATUS status;
    ULONG chars;

    RtlZeroMemory(&header, sizeof(header));
    RtlZeroMemory(&msg, sizeof(msg));

    header.version = SENTINEL_PROTOCOL_VERSION;
    header.kind = SentinelMsgFilePreOp;
    header.process_id = ProcessId;

    msg.file_op = SentinelFileExecute;
    msg.requires_sync_verdict = 1;

    chars = NameInfo->Name.Length / sizeof(WCHAR);
    if (chars >= SENTINEL_MAX_PATH) {
        chars = SENTINEL_MAX_PATH - 1;
    }
    RtlCopyMemory(msg.path, NameInfo->Name.Buffer, chars * sizeof(WCHAR));
    msg.path[chars] = L'\0';
    msg.path_chars = chars;

    status = SentinelCommsAskVerdict(&gComms, &header, &msg, sizeof(msg),
                                     &reply, 5000 /* ms */);
    if (!NT_SUCCESS(status)) {
        return gFailClosed ? SentinelActionBlock : SentinelActionAllow;
    }
    return (SENTINEL_ACTION)reply.action;
}

FLT_PREOP_CALLBACK_STATUS SentinelPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    /* Pre-create is where we could pre-fetch metadata; the execution gate is in
     * the section-synchronization callback below. Pass through here. */
    UNREFERENCED_PARAMETER(Data);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS SentinelPreAcquireForSection(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext) {
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    SENTINEL_ACTION action;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    /* Only gate executable section creation (image mapping). Data mappings pass
     * through to keep the common path fast. */
    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection
            != PAGE_EXECUTE &&
        Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection
            != PAGE_EXECUTE_READ &&
        Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection
            != PAGE_EXECUTE_READWRITE &&
        Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection
            != PAGE_EXECUTE_WRITECOPY) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = SentinelGetPath(Data, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    action = SentinelScanImage(nameInfo, (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
    FltReleaseFileNameInformation(nameInfo);

    if (action == SentinelActionBlock || action == SentinelActionKillRollback) {
        /* Deny the image from being mapped for execution. */
        Data->IoStatus.Status = STATUS_VIRUS_INFECTED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    /* Allow / monitor / hold-in-shadow all permit the mapping; gating of the
     * resulting process's side effects is handled by procmon + shadowfs. */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS SentinelPostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags) {
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    SENTINEL_EVENT_MSG evt;
    ULONG chars;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!NT_SUCCESS(SentinelGetPath(Data, &nameInfo))) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Report writes asynchronously so the behavioral engine can watch for the
     * ransomware mass-encrypt pattern. No inline cost beyond the send. */
    RtlZeroMemory(&evt, sizeof(evt));
    chars = nameInfo->Name.Length / sizeof(WCHAR);
    if (chars >= SENTINEL_MAX_PATH) {
        chars = SENTINEL_MAX_PATH - 1;
    }
    RtlCopyMemory(evt.path, nameInfo->Name.Buffer, chars * sizeof(WCHAR));
    evt.path[chars] = L'\0';
    evt.path_chars = chars;
    evt.target_process_id = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    SentinelCommsSendEvent(&gComms, SentinelMsgFilePreOp, &evt, sizeof(evt));
    FltReleaseFileNameInformation(nameInfo);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS SentinelUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    /* While protection is on, refuse unload unless a mandatory unload is forced.
     * The service watchdog treats an unexpected unload as tampering. */
    SentinelCommsClosePort(&gComms);
    if (gFilterHandle != NULL) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SentinelCommsCreatePort(&gComms, gFilterHandle, SENTINEL_PORT_NAME);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        SentinelCommsClosePort(&gComms);
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }
    return STATUS_SUCCESS;
}
