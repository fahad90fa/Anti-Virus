/*
 * Sentinel AV — shared kernel <-> user definitions.
 *
 * This header is included by BOTH the kernel drivers (C, built with the WDK) and
 * the user-mode engine (C++). It defines the wire format of the filter
 * communication port: the messages the drivers send up to the engine (scan
 * requests, behavioral events) and the verdicts the engine sends back down.
 *
 * Keep this strictly C-compatible and fixed-width. No pointers cross the
 * boundary; file content travels in a shared-memory section referenced by offset.
 */
#ifndef SENTINEL_DRIVERS_SHARED_DEFS_H
#define SENTINEL_DRIVERS_SHARED_DEFS_H

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif

/* Name of the FltMgr communication port the engine connects to. */
#define SENTINEL_PORT_NAME L"\\SentinelFsPort"
#define SENTINEL_PROCMON_PORT_NAME L"\\SentinelProcPort"
#define SENTINEL_NET_PORT_NAME L"\\SentinelNetPort"

#define SENTINEL_PROTOCOL_VERSION 1u
#define SENTINEL_MAX_PATH 1024u
#define SENTINEL_MAX_INLINE_DATA 4096u

/* Verdict actions sent from the engine back to a driver. Values MUST match
 * sentinel::Action in engine/include/sentinel/core/types.h. */
typedef enum _SENTINEL_ACTION {
    SentinelActionAllow = 0,
    SentinelActionMonitor = 1,
    SentinelActionHoldInShadow = 2,
    SentinelActionBlock = 3,
    SentinelActionKillRollback = 4
} SENTINEL_ACTION;

/* Risk levels. MUST match sentinel::RiskLevel. */
typedef enum _SENTINEL_RISK {
    SentinelRiskTrusted = 0,
    SentinelRiskUnknown = 1,
    SentinelRiskLow = 2,
    SentinelRiskSuspicious = 3,
    SentinelRiskMalicious = 4
} SENTINEL_RISK;

/* Message kinds, kernel -> user. */
typedef enum _SENTINEL_MSG_KIND {
    SentinelMsgFilePreOp = 1,       /* a file is about to be opened/executed */
    SentinelMsgProcessCreate = 2,
    SentinelMsgProcessExit = 3,
    SentinelMsgThreadCreate = 4,
    SentinelMsgImageLoad = 5,
    SentinelMsgRegistryOp = 6,
    SentinelMsgHandleOp = 7,        /* object-callback: handle to protected proc */
    SentinelMsgNetworkConnect = 8,
    SentinelMsgHeartbeat = 9
} SENTINEL_MSG_KIND;

/* Operation hint for a file pre-op. */
typedef enum _SENTINEL_FILE_OP {
    SentinelFileOpen = 0,
    SentinelFileCreate = 1,
    SentinelFileWrite = 2,
    SentinelFileExecute = 3,   /* image section create — the synchronous gate */
    SentinelFileRename = 4
} SENTINEL_FILE_OP;

/* Fixed message header prefixing every kernel -> user message. The FltMgr
 * FILTER_MESSAGE_HEADER precedes THIS in the actual buffer. */
typedef struct _SENTINEL_MSG_HEADER {
    uint32_t version;       /* SENTINEL_PROTOCOL_VERSION */
    uint32_t kind;          /* SENTINEL_MSG_KIND */
    uint64_t sequence;      /* monotonically increasing */
    uint64_t timestamp_100ns;
    uint32_t process_id;
    uint32_t thread_id;
    uint32_t payload_bytes; /* bytes following this header */
    uint32_t reserved;
} SENTINEL_MSG_HEADER;

/* Payload for SentinelMsgFilePreOp. The engine replies with SENTINEL_REPLY. */
typedef struct _SENTINEL_FILE_MSG {
    uint32_t file_op;               /* SENTINEL_FILE_OP */
    uint32_t path_chars;            /* length of path in WCHARs (no NUL) */
    uint64_t file_size;
    uint64_t section_offset;        /* offset into the shared section for content */
    uint32_t section_bytes;         /* bytes of content available in the section */
    uint32_t requires_sync_verdict; /* 1 if the driver is holding the op */
    uint16_t path[SENTINEL_MAX_PATH]; /* UTF-16 image/file path */
} SENTINEL_FILE_MSG;

/* Payload for process/thread/image/registry/handle/network events (async). */
typedef struct _SENTINEL_EVENT_MSG {
    uint32_t parent_process_id;
    uint32_t target_process_id;     /* remote target for inject/handle events */
    uint32_t extra;                 /* op-specific flags (e.g. desired access) */
    uint32_t path_chars;
    uint16_t path[SENTINEL_MAX_PATH]; /* image path / key / remote host */
} SENTINEL_EVENT_MSG;

/* Reply, user -> kernel, for a synchronous request. */
typedef struct _SENTINEL_REPLY {
    uint64_t sequence;      /* echoes the request header sequence */
    uint32_t action;        /* SENTINEL_ACTION */
    uint32_t risk;          /* SENTINEL_RISK */
    uint32_t score_milli;   /* fused score * 1000 */
    uint32_t reserved;
} SENTINEL_REPLY;

/* Connection context the user-mode engine sends when it connects to the port,
 * so the kernel can reject a client speaking a different protocol version before
 * any message is exchanged (the connect is refused with STATUS_REVISION_MISMATCH). */
typedef struct _SENTINEL_CONNECT_CONTEXT {
    uint32_t version;       /* must equal SENTINEL_PROTOCOL_VERSION */
    uint32_t reserved;
} SENTINEL_CONNECT_CONTEXT;

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* SENTINEL_DRIVERS_SHARED_DEFS_H */
