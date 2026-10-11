/*
 * Sentinel AV — kernel-side communication-port helpers (declarations).
 *
 * Thin wrappers over the FltMgr communication-port API used by the minifilter
 * and the other drivers to talk to the user-mode engine. The engine connects to
 * the port, the driver sends messages up, and for synchronous requests waits for
 * a SENTINEL_REPLY. Shared-memory buffers carry file content to avoid copies.
 *
 * Kernel-only (depends on fltKernel.h). Built with the WDK.
 */
#ifndef SENTINEL_DRIVERS_COMMS_H
#define SENTINEL_DRIVERS_COMMS_H

#include <fltKernel.h>
#include "shared_defs.h"

typedef struct _SENTINEL_COMMS {
    PFLT_PORT ServerPort;    /* the listening server port */
    PFLT_PORT ClientPort;    /* the connected engine (one trusted client) */
    PFLT_FILTER Filter;
    volatile LONG64 Sequence;
    BOOLEAN EngineConnected;
} SENTINEL_COMMS, *PSENTINEL_COMMS;

/* Create/tear down the communication port. Only a PPL anti-malware engine
 * process is allowed to connect (enforced in the connect callback via the
 * security descriptor built here). */
NTSTATUS SentinelCommsCreatePort(_Inout_ PSENTINEL_COMMS Comms,
                                 _In_ PFLT_FILTER Filter,
                                 _In_ PCWSTR PortName);
VOID SentinelCommsClosePort(_Inout_ PSENTINEL_COMMS Comms);

/* Connect/disconnect notification callbacks (registered with the port). */
NTSTATUS SentinelPortConnect(_In_ PFLT_PORT ClientPort,
                             _In_opt_ PVOID ServerPortCookie,
                             _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                             _In_ ULONG SizeOfContext,
                             _Outptr_result_maybenull_ PVOID *ConnectionCookie);
VOID SentinelPortDisconnect(_In_opt_ PVOID ConnectionCookie);

/* Send a synchronous file pre-op request and block for a verdict. On timeout or
 * a disconnected engine, Reply->action is set to SentinelActionAllow (fail-open
 * for availability; the policy knob SentinelFailClosed can flip this). */
NTSTATUS SentinelCommsAskVerdict(_In_ PSENTINEL_COMMS Comms,
                                 _In_ SENTINEL_MSG_HEADER *Header,
                                 _In_ PVOID Payload,
                                 _In_ ULONG PayloadBytes,
                                 _Out_ SENTINEL_REPLY *Reply,
                                 _In_ LONGLONG TimeoutMs);

/* Send an asynchronous event (no reply expected). */
NTSTATUS SentinelCommsSendEvent(_In_ PSENTINEL_COMMS Comms,
                                _In_ SENTINEL_MSG_KIND Kind,
                                _In_ PVOID Payload,
                                _In_ ULONG PayloadBytes);

#endif /* SENTINEL_DRIVERS_COMMS_H */
