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
#elif defined(_KERNEL_MODE)
/* Kernel mode: do NOT pull in the user-mode <stdint.h> — it conflicts with the
 * WDK's km CRT headers (duplicate __CRTDECL / _VCRUNTIME_* definitions). Define
 * the fixed-width types from the MSVC intrinsics instead. (ntddk.h/fltKernel.h
 * are already included by the driver before this header.) */
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
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

/* ---- Sensor control-device transport (procmon, netfilter) -----------------
 * The minifilters (fsfilter, shadowfs) talk to the engine over an FltMgr
 * communication port (see comms.h). The non-minifilter sensor drivers cannot
 * use an FltMgr port (they have no PFLT_FILTER), so they expose a secured
 * control device and use an inverted-call IOCTL transport (sensor_comms.c).
 * The wire MESSAGES are the SAME structs above (SENTINEL_MSG_HEADER +
 * SENTINEL_EVENT_MSG, SENTINEL_REPLY, SENTINEL_CONNECT_CONTEXT); only the
 * transport differs, so SENTINEL_PROTOCOL_VERSION is unchanged. */

/* Control-device + symlink names, and the user-mode CreateFile path. */
#define SENTINEL_PROC_DEVICE_NAME   L"\\Device\\SentinelProc"
#define SENTINEL_PROC_SYMLINK_NAME  L"\\??\\SentinelProc"
#define SENTINEL_PROC_USER_PATH     L"\\\\.\\SentinelProc"
#define SENTINEL_NET_DEVICE_NAME    L"\\Device\\SentinelNet"
#define SENTINEL_NET_SYMLINK_NAME   L"\\??\\SentinelNet"
#define SENTINEL_NET_USER_PATH      L"\\\\.\\SentinelNet"

/* Self-contained CTL_CODE expansion so this header needs NOTHING from
 * <winioctl.h> (user) or <wdm.h> (kernel) and both sides agree byte-for-byte.
 * It reproduces CTL_CODE's exact bit layout:
 *   value = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method */
#define SENTINEL_FILE_DEVICE        0x00008000u  /* custom/vendor device type */
#define SENTINEL_METHOD_BUFFERED    0x0u
#define SENTINEL_FILE_ANY_ACCESS    0x0u
#define SENTINEL_FILE_READ_ACCESS   0x1u
#define SENTINEL_FILE_WRITE_ACCESS  0x2u
#define SENTINEL_CTL_CODE(func, access) \
    ( ((uint32_t)(SENTINEL_FILE_DEVICE)        << 16) \
    | ((uint32_t)(access)                      << 14) \
    | ((uint32_t)(func)                        <<  2) \
    | ((uint32_t)(SENTINEL_METHOD_BUFFERED)) )

/* IOCTLs (all METHOD_BUFFERED: the kernel owns a bounded system-buffer copy,
 * never a raw user pointer). Values: CONNECT=0x8000E000, GET_EVENT=0x80006004,
 * POST_VERDICT=0x8000A008, REGISTER_PID=0x8000A00C. */
#define IOCTL_SENTINEL_CONNECT \
    SENTINEL_CTL_CODE(0x800u, SENTINEL_FILE_READ_ACCESS | SENTINEL_FILE_WRITE_ACCESS)
#define IOCTL_SENTINEL_GET_EVENT \
    SENTINEL_CTL_CODE(0x801u, SENTINEL_FILE_READ_ACCESS)
#define IOCTL_SENTINEL_POST_VERDICT \
    SENTINEL_CTL_CODE(0x802u, SENTINEL_FILE_WRITE_ACCESS)
#define IOCTL_SENTINEL_REGISTER_PID \
    SENTINEL_CTL_CODE(0x803u, SENTINEL_FILE_WRITE_ACCESS)

/* Set in the (otherwise zero) SENTINEL_MSG_HEADER.reserved for an event that
 * requires a synchronous POST_VERDICT reply (procmon's process-create gate).
 * The struct layout is unchanged. */
#define SENTINEL_FLAG_SYNC_VERDICT  0x00000001u

/* IOCTL_SENTINEL_REGISTER_PID payload: the engine registers the PIDs of the
 * protected Sentinel processes (service + watchdog) for self-protection. */
#define SENTINEL_MAX_REGISTER_PIDS  8u
typedef struct _SENTINEL_REGISTER_PID_REQUEST {
    uint32_t count;                             /* <= SENTINEL_MAX_REGISTER_PIDS */
    uint32_t pids[SENTINEL_MAX_REGISTER_PIDS];
} SENTINEL_REGISTER_PID_REQUEST;

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* SENTINEL_DRIVERS_SHARED_DEFS_H */
