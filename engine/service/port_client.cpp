// Filter-service transport: the user-mode side of the kernel <-> engine channel.
// On Windows it connects to the minifilter's FltMgr communication port, receives
// scan requests + behavioral events, routes them through the existing Engine, and
// replies with verdicts. The heavy detection logic is the same Engine the CLI
// uses; this file is only transport + protocol validation.
//
// Off Windows there is no filter port, so RunFilterService is a stub returning
// Unsupported; the folder watcher drives scanning in the portable build instead.
#include "sentinel/service/filter_service.h"

#include "sentinel/core/logging.h"

#if defined(_WIN32)

#include <windows.h>
#include <fltUser.h>

#include <string>
#include <vector>

#include "../../drivers/common/shared_defs.h"
#include "sentinel/behavior/action_graph.h"

namespace sentinel {
namespace {

// Map an engine Verdict to the kernel action/risk enums (values match
// SENTINEL_ACTION / SENTINEL_RISK in shared_defs.h).
void FillReply(const Verdict& v, std::uint64_t sequence, SENTINEL_REPLY* reply) {
    reply->sequence = sequence;
    reply->action = static_cast<std::uint32_t>(v.action);
    reply->risk = static_cast<std::uint32_t>(v.level);
    reply->score_milli = static_cast<std::uint32_t>(v.score * 1000.0);
    reply->reserved = 0;
}

std::string WideToUtf8(const std::uint16_t* wide, std::uint32_t chars) {
    if (chars == 0) return std::string();
    int n = ::WideCharToMultiByte(CP_UTF8, 0,
                                  reinterpret_cast<const wchar_t*>(wide),
                                  static_cast<int>(chars), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string out(static_cast<std::size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<const wchar_t*>(wide),
                          static_cast<int>(chars), out.data(), n, nullptr, nullptr);
    return out;
}

// Map an async kernel event to an action-graph ActivityEvent type.
bool MapEventKind(std::uint32_t kind, std::uint32_t extra, ActionType* out) {
    switch (kind) {
        case SentinelMsgProcessCreate: *out = ActionType::ProcessStart; return true;
        case SentinelMsgProcessExit:   *out = ActionType::ProcessExit;  return true;
        case SentinelMsgThreadCreate:
            // High bit of `extra` marks a remote thread (injection tail).
            *out = (extra & 0x80000000u) ? ActionType::RemoteThreadCreate
                                         : ActionType::ThreadCreate;
            return true;
        case SentinelMsgImageLoad:     *out = ActionType::ImageLoad; return true;
        case SentinelMsgRegistryOp:    *out = ActionType::RegistryPersistence; return true;
        case SentinelMsgNetworkConnect:*out = ActionType::NetworkConnect; return true;
        default: return false;
    }
}

}  // namespace

Status RunFilterService(Engine& engine, const FilterServiceOptions& options,
                        std::atomic<bool>& stop) {
    HANDLE port = INVALID_HANDLE_VALUE;
    HRESULT hr = ::FilterConnectCommunicationPort(SENTINEL_PORT_NAME, 0, nullptr, 0,
                                                  nullptr, &port);
    if (hr != S_OK) {
        return Status::Error(ErrorCode::IoError,
                             "FilterConnectCommunicationPort failed (hr=" +
                                 std::to_string(hr) + "); is the minifilter loaded?");
    }
    SENTINEL_LOG(Info) << "connected to minifilter port " << "SentinelFsPort";

    OVERLAPPED ov{};
    ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (ov.hEvent == nullptr) {
        ::CloseHandle(port);
        return Status::Error(ErrorCode::Internal, "CreateEvent failed");
    }

    // Buffer: FILTER_MESSAGE_HEADER + our header + the largest payload.
    struct RequestBuffer {
        FILTER_MESSAGE_HEADER header;
        SENTINEL_MSG_HEADER msg;
        union {
            SENTINEL_FILE_MSG file;
            SENTINEL_EVENT_MSG event;
        } body;
    };

    Status result = Status::Ok();
    while (!stop.load()) {
        RequestBuffer req;
        ::ZeroMemory(&req, sizeof(req));
        ::ResetEvent(ov.hEvent);

        hr = ::FilterGetMessage(port, &req.header, sizeof(req), &ov);
        if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
            // Poll for completion so we can honor `stop` promptly.
            for (;;) {
                DWORD w = ::WaitForSingleObject(ov.hEvent, 500);
                if (w == WAIT_OBJECT_0) break;
                if (stop.load()) { ::CancelIoEx(port, &ov); goto done; }
            }
            DWORD bytes = 0;
            if (!::GetOverlappedResult(port, &ov, &bytes, FALSE)) {
                result = Status::Error(ErrorCode::IoError, "GetOverlappedResult failed");
                break;
            }
        } else if (hr != S_OK) {
            // Port likely disconnected (service stopping / driver unloaded).
            SENTINEL_LOG(Warn) << "FilterGetMessage hr=" << hr << "; stopping pump";
            break;
        }

        // Protocol validation: reject anything we do not understand cleanly.
        if (req.msg.version != SENTINEL_PROTOCOL_VERSION) {
            SENTINEL_LOG(Warn) << "rejecting message with protocol version "
                               << req.msg.version << " (expected "
                               << SENTINEL_PROTOCOL_VERSION << ")";
            // For a sync request, fail-safe so the kernel is never left waiting.
            if (req.msg.kind == SentinelMsgFilePreOp && req.body.file.requires_sync_verdict) {
                struct { FILTER_REPLY_HEADER h; SENTINEL_REPLY r; } rb{};
                rb.h.MessageId = req.header.MessageId;
                rb.h.Status = 0;
                Verdict v;
                v.action = options.fail_closed ? Action::Block : Action::Allow;
                v.level = RiskLevel::Unknown;
                FillReply(v, req.msg.sequence, &rb.r);
                ::FilterReplyMessage(port, &rb.h, sizeof(rb));
            }
            continue;
        }

        if (req.msg.kind == SentinelMsgFilePreOp && req.body.file.requires_sync_verdict) {
            // Synchronous execute gate: scan and reply with a verdict. The kernel
            // holds the operation until this reply (or its own timeout).
            std::uint32_t chars = req.body.file.path_chars;
            if (chars >= SENTINEL_MAX_PATH) chars = SENTINEL_MAX_PATH - 1;
            std::string path = WideToUtf8(req.body.file.path, chars);

            Verdict v;
            if (!path.empty()) {
                FileScanResult r = engine.ScanFile(path);
                v = r.verdict;
            } else {
                v.action = options.fail_closed ? Action::Block : Action::Allow;
                v.level = RiskLevel::Unknown;
            }

            struct { FILTER_REPLY_HEADER h; SENTINEL_REPLY r; } rb{};
            rb.h.MessageId = req.header.MessageId;
            rb.h.Status = 0;
            FillReply(v, req.msg.sequence, &rb.r);
            HRESULT rhr = ::FilterReplyMessage(port, &rb.h, sizeof(rb));
            if (rhr != S_OK) {
                SENTINEL_LOG(Warn) << "FilterReplyMessage hr=" << rhr;
            }
        } else {
            // Asynchronous behavioral event: feed the action graph. No reply.
            ActionType type;
            if (MapEventKind(req.msg.kind, req.body.event.extra, &type)) {
                std::uint32_t chars = req.body.event.path_chars;
                if (chars >= SENTINEL_MAX_PATH) chars = SENTINEL_MAX_PATH - 1;
                std::string image = WideToUtf8(req.body.event.path, chars);
                ActivityEvent ev;
                ev.type = type;
                ev.timestamp_ms = engine.NowMs();
                ev.target = image;
                ev.target_pid = req.body.event.target_process_id;
                engine.ObserveProcessAction(req.msg.process_id,
                                            req.body.event.parent_process_id,
                                            image, ev);
            }
        }
    }

done:
    ::CloseHandle(ov.hEvent);
    ::CloseHandle(port);
    SENTINEL_LOG(Info) << "filter service stopped";
    return result;
}

}  // namespace sentinel

#else  // non-Windows stub

namespace sentinel {

Status RunFilterService(Engine&, const FilterServiceOptions&, std::atomic<bool>&) {
    SENTINEL_LOG(Debug) << "filter service is Windows-only; use `watch` on this platform";
    return Status::Error(ErrorCode::Unsupported, "filter service requires Windows");
}

}  // namespace sentinel

#endif
