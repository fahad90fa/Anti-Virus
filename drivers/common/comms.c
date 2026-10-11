/*
 * Sentinel AV — kernel-side communication-port helpers (implementation).
 *
 * Built with the WDK; kernel-mode C. Not compiled in the portable Linux build.
 */
#include "comms.h"

/* Only a Protected Process Light anti-malware process should connect. We build
 * a security descriptor allowing SYSTEM and Administrators; in production this
 * is further restricted and the client's PPL signing level is checked in the
 * connect callback. */
NTSTATUS SentinelCommsCreatePort(_Inout_ PSENTINEL_COMMS Comms,
                                 _In_ PFLT_FILTER Filter,
                                 _In_ PCWSTR PortName) {
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING name;

    if (Comms == NULL || Filter == NULL || PortName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Comms, sizeof(*Comms));
    Comms->Filter = Filter;
    Comms->Sequence = 0;
    Comms->EngineConnected = FALSE;

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&name, PortName);
    InitializeObjectAttributes(&oa, &name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, sd);

    /* A single trusted client (the engine). MaxConnections = 1. */
    status = FltCreateCommunicationPort(Filter, &Comms->ServerPort, &oa, Comms,
                                        SentinelPortConnect,
                                        SentinelPortDisconnect,
                                        NULL /* message notify set per-driver */,
                                        1);
    FltFreeSecurityDescriptor(sd);
    return status;
}

VOID SentinelCommsClosePort(_Inout_ PSENTINEL_COMMS Comms) {
    if (Comms == NULL) {
        return;
    }
    if (Comms->ServerPort != NULL) {
        FltCloseCommunicationPort(Comms->ServerPort);
        Comms->ServerPort = NULL;
    }
    Comms->EngineConnected = FALSE;
}

NTSTATUS SentinelPortConnect(_In_ PFLT_PORT ClientPort,
                             _In_opt_ PVOID ServerPortCookie,
                             _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                             _In_ ULONG SizeOfContext,
                             _Outptr_result_maybenull_ PVOID *ConnectionCookie) {
    PSENTINEL_COMMS comms = (PSENTINEL_COMMS)ServerPortCookie;

    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    if (comms == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Exactly one engine client. */
    comms->ClientPort = ClientPort;
    comms->EngineConnected = TRUE;
    *ConnectionCookie = comms;
    return STATUS_SUCCESS;
}

VOID SentinelPortDisconnect(_In_opt_ PVOID ConnectionCookie) {
    PSENTINEL_COMMS comms = (PSENTINEL_COMMS)ConnectionCookie;
    if (comms == NULL) {
        return;
    }
    FltCloseClientPort(comms->Filter, &comms->ClientPort);
    comms->ClientPort = NULL;
    comms->EngineConnected = FALSE;
}

NTSTATUS SentinelCommsAskVerdict(_In_ PSENTINEL_COMMS Comms,
                                 _In_ SENTINEL_MSG_HEADER *Header,
                                 _In_ PVOID Payload,
                                 _In_ ULONG PayloadBytes,
                                 _Out_ SENTINEL_REPLY *Reply,
                                 _In_ LONGLONG TimeoutMs) {
    NTSTATUS status;
    LARGE_INTEGER timeout;
    ULONG replyLength = sizeof(SENTINEL_REPLY);
    /* Assemble header+payload into a single contiguous message buffer. For
     * brevity this uses a stack buffer sized for the fixed messages; large file
     * content travels via the shared section referenced in the payload. */
    UCHAR buffer[sizeof(SENTINEL_MSG_HEADER) + sizeof(SENTINEL_FILE_MSG)];

    if (Comms == NULL || Header == NULL || Reply == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Reply, sizeof(*Reply));

    /* Fail-open if the engine is not connected: we must not deadlock the system
     * when protection is not running. A fail-closed policy build flips this. */
    if (!Comms->EngineConnected || Comms->ClientPort == NULL) {
        Reply->sequence = Header->sequence;
        Reply->action = SentinelActionAllow;
        Reply->risk = SentinelRiskUnknown;
        return STATUS_PORT_DISCONNECTED;
    }

    if (sizeof(SENTINEL_MSG_HEADER) + PayloadBytes > sizeof(buffer)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Header->sequence = (uint64_t)InterlockedIncrement64(&Comms->Sequence);
    Header->payload_bytes = PayloadBytes;
    RtlCopyMemory(buffer, Header, sizeof(SENTINEL_MSG_HEADER));
    if (Payload != NULL && PayloadBytes > 0) {
        RtlCopyMemory(buffer + sizeof(SENTINEL_MSG_HEADER), Payload, PayloadBytes);
    }

    timeout.QuadPart = -(TimeoutMs * 10000LL); /* relative, 100ns units */

    status = FltSendMessage(Comms->Filter, &Comms->ClientPort, buffer,
                            sizeof(SENTINEL_MSG_HEADER) + PayloadBytes,
                            Reply, &replyLength, &timeout);

    if (status == STATUS_TIMEOUT || !NT_SUCCESS(status)) {
        /* On timeout, fail-open for availability. */
        Reply->sequence = Header->sequence;
        Reply->action = SentinelActionAllow;
        Reply->risk = SentinelRiskUnknown;
        return status;
    }
    return STATUS_SUCCESS;
}

NTSTATUS SentinelCommsSendEvent(_In_ PSENTINEL_COMMS Comms,
                                _In_ SENTINEL_MSG_KIND Kind,
                                _In_ PVOID Payload,
                                _In_ ULONG PayloadBytes) {
    SENTINEL_MSG_HEADER header;
    UCHAR buffer[sizeof(SENTINEL_MSG_HEADER) + sizeof(SENTINEL_EVENT_MSG)];

    if (Comms == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!Comms->EngineConnected || Comms->ClientPort == NULL) {
        return STATUS_PORT_DISCONNECTED;
    }
    if (sizeof(SENTINEL_MSG_HEADER) + PayloadBytes > sizeof(buffer)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&header, sizeof(header));
    header.version = SENTINEL_PROTOCOL_VERSION;
    header.kind = (uint32_t)Kind;
    header.sequence = (uint64_t)InterlockedIncrement64(&Comms->Sequence);
    header.payload_bytes = PayloadBytes;

    RtlCopyMemory(buffer, &header, sizeof(header));
    if (Payload != NULL && PayloadBytes > 0) {
        RtlCopyMemory(buffer + sizeof(header), Payload, PayloadBytes);
    }

    /* Asynchronous: no reply buffer. */
    return FltSendMessage(Comms->Filter, &Comms->ClientPort, buffer,
                          sizeof(header) + PayloadBytes, NULL, NULL, NULL);
}
