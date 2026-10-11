// Filter-port client: the user-mode side of the kernel <-> engine channel. On
// Windows it connects to the minifilter's FltMgr communication port, receives
// scan requests and events, and replies with verdicts. The heavy scanning logic
// is the same Engine the CLI uses; this file is only the transport.
//
// On non-Windows (the portable build/CI) there is no filter port, so this
// compiles to a no-op stub — the engine is still fully exercised through the CLI
// and the folder watcher.
#include "sentinel/core/logging.h"

#if defined(_WIN32)

#include <windows.h>
#include <fltuser.h>

#include "sentinel/engine.h"
#include "../../drivers/common/shared_defs.h"

namespace sentinel {

// Connects to SENTINEL_PORT_NAME, pumps messages, and replies with verdicts.
// A full implementation runs a pool of threads calling FilterGetMessage /
// FilterReplyMessage; sketched here with the real API surface.
class PortClient {
public:
    explicit PortClient(Engine& engine) : engine_(engine) {}

    bool Connect() {
        HRESULT hr = FilterConnectCommunicationPort(
            SENTINEL_PORT_NAME, 0, nullptr, 0, nullptr, &port_);
        if (hr != S_OK) {
            SENTINEL_LOG(Warn) << "filter port connect failed: " << hr;
            return false;
        }
        return true;
    }

    void PumpOnce() {
        struct {
            FILTER_MESSAGE_HEADER header;
            SENTINEL_MSG_HEADER msg;
            SENTINEL_FILE_MSG file;
        } request{};

        HRESULT hr = FilterGetMessage(port_, &request.header,
                                      sizeof(request), nullptr);
        if (hr != S_OK) return;

        // Scan by path; reply with the fused verdict mapped to SENTINEL_ACTION.
        char utf8[SENTINEL_MAX_PATH * 2] = {0};
        WideCharToMultiByte(CP_UTF8, 0,
                            reinterpret_cast<wchar_t*>(request.file.path), -1,
                            utf8, sizeof(utf8), nullptr, nullptr);
        FileScanResult r = engine_.ScanFile(utf8);

        struct {
            FILTER_REPLY_HEADER header;
            SENTINEL_REPLY reply;
        } response{};
        response.header.MessageId = request.header.MessageId;
        response.header.Status = 0;
        response.reply.sequence = request.msg.sequence;
        response.reply.action = static_cast<uint32_t>(r.verdict.action);
        response.reply.risk = static_cast<uint32_t>(r.verdict.level);
        response.reply.score_milli = static_cast<uint32_t>(r.verdict.score * 1000.0);
        FilterReplyMessage(port_, &response.header, sizeof(response));
    }

private:
    Engine& engine_;
    HANDLE port_ = INVALID_HANDLE_VALUE;
};

}  // namespace sentinel

#else  // non-Windows stub

namespace sentinel {
// No filter port off Windows; the folder watcher drives scanning instead.
void PortClientUnavailable() {
    SENTINEL_LOG(Debug) << "filter port client is Windows-only; using folder watcher";
}
}  // namespace sentinel

#endif
