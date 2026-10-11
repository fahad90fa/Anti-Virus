# IPC protocol — engine (C++) ⇄ UI (C#)

This is the contract between the always-on engine service (C++) and the C#
dashboard/tray. It is separate from the kernel⇄engine filter-port protocol
(`drivers/common/shared_defs.h`); this one is a local, authenticated channel the
UI uses to show status and issue user actions.

## Transport

- **Windows:** a named pipe `\\.\pipe\SentinelEngine` secured so only the
  interactive user and the service account can connect. The service runs as PPL;
  the UI is an ordinary app and gets a **read-mostly** view plus a small set of
  user-authorized actions.
- **Dev/other platforms:** a local TCP loopback socket on `127.0.0.1:51515`
  (used by the Linux build of the engine for the CLI/integration tests).

## Framing

Newline-delimited JSON (one JSON object per line, UTF-8). Each message has a
`type` and a monotonic `id`; replies carry the same `id`.

```
{ "type": "<request|event|reply>", "id": <n>, "op": "<name>", ... }
```

The engine pushes `event` messages unsolicited (detections, status changes); the
UI sends `request` messages and receives a matching `reply`.

## Requests (UI → engine)

| op | params | reply |
| --- | --- | --- |
| `get_status` | — | engine state, versions, counters, containment state |
| `scan_path` | `path`, `recursive` | a `TreeScanResult` summary |
| `list_quarantine` | — | array of quarantine entries |
| `restore_quarantine` | `id`, `dest?` | ok/error (user-authorized) |
| `purge_quarantine` | `id` | ok/error (user-authorized) |
| `get_timeline` | `pid?`, `limit?` | array of timeline events |
| `set_config` | `key`, `value` | ok/error (admin only) |
| `run_selftest` | — | self-test result (EICAR detection, etc.) |
| `release_containment` | — | ok/error (admin only) |

## Events (engine → UI)

| op | payload |
| --- | --- |
| `detection` | path/pid, verdict (level, action, score), top signals, timestamp |
| `status` | protection on/off, last update, signature version |
| `containment` | isolated/normal + reason |
| `update` | signature update applied (version) |
| `tamper` | self-protection or integrity event |

## Verdict payload shape

```json
{
  "level": "Malicious",
  "action": "KillAndRollback",
  "score": 0.97,
  "summary": "EICAR standard antivirus test file",
  "signals": [
    { "source": "YaraRule", "level": "Malicious", "confidence": 0.95,
      "detail": "Eicar_Test_File", "rule_id": "Eicar_Test_File" }
  ]
}
```

`level`, `action`, and `source` are the string forms of the engine enums
(`sentinel::RiskLevel`, `Action`, `SignalSource`) — see
`engine/include/sentinel/core/types.h`. The numeric action values also match the
kernel protocol's `SENTINEL_ACTION`, so a verdict can round-trip
kernel → engine → UI without re-mapping.

## Authorization

- The UI never gets raw memory or kill rights. Destructive actions
  (`restore_quarantine`, `purge_quarantine`, `set_config`,
  `release_containment`) require the caller to be an elevated admin; the engine
  re-checks the token on every such request.
- The channel is integrity-checked: the UI pins the service's code identity, and
  the service pins the UI's, so malware cannot impersonate either end.
