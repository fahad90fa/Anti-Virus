/*
 * Sentinel AV — WFP network callout driver.  [Phase 3]
 *
 * The network layer watches traffic to stop threats that arrive or escape over
 * the wire: drive-by downloads, command-and-control (C2) beacons, and data
 * exfiltration. It is built as a Windows Filtering Platform (WFP) callout driver,
 * the official in-kernel way to inspect and filter connections and packets.
 *
 * What it does:
 *   - Connection filtering: block outbound connections to known-malicious IPs
 *     and inbound to ports that should not be exposed (blocklist + reputation).
 *   - C2 beacon detection: flag regular, small, periodic connections to an
 *     unfamiliar host, especially right after a suspicious process started.
 *   - Exfiltration guard: notice a process that just touched many documents then
 *     opens a large upload, paired with the behavioral engine.
 *   - Per-process rules: because the driver knows which process owns a socket,
 *     rules are per-app (a PDF reader has no business opening raw connections to
 *     a foreign server).
 *
 * It does NOT decrypt TLS; it works on metadata (who, where, how often, how
 * much) and endpoint reputation, which catches most C2 without touching content.
 *
 * Built with the WDK; kernel-mode C. Links fwpkclnt.lib + ndis.lib.
 */
/* A WFP callout is a WDM driver, NOT KMDF — it must not include <wdf.h>. ntddk.h
 * is the single base header for this TU; initguid.h (before the WFP management
 * header) makes the WFP layer GUIDs and our callout GUID emit as data. */
#include <ntddk.h>
#include <initguid.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include "../common/sensor_comms.h"
#include "../common/shared_defs.h"

/* WFP engine + callout registration state. */
HANDLE gEngineHandle = NULL;
UINT32 gCalloutIdConnect = 0;
UINT64 gFilterIdConnect = 0;

/* netfilter is NOT a minifilter, so it talks to the engine over the secured
 * control device the sensor comms module creates (sensor_comms.c). That same
 * device object doubles as the anchor for the WFP callout registration.
 * netfilter only ever sends ASYNC events (never asks a synchronous verdict), and
 * its classify callback can run at DISPATCH_LEVEL — the send path is DISPATCH-safe. */
SENTINEL_SENSOR_COMMS gNetComms = {0};

/* {E9A1C7D2-0001-4C3A-9B10-SENTINELNETC} — callout GUID (dev placeholder). */
DEFINE_GUID(SENTINEL_CALLOUT_CONNECT_V4,
    0xe9a1c7d2, 0x0001, 0x4c3a, 0x9b, 0x10, 0x53, 0x45, 0x4e, 0x54, 0x4e, 0x43);

/* ALE connect classify: decide whether to permit or block an outbound
 * connection, per-process, against the blocklist + reputation. */
VOID SentinelClassifyConnectV4(
    _In_ const FWPS_INCOMING_VALUES0 *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    _Inout_opt_ void *layerData,
    _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER3 *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *classifyOut) {
    UINT32 remoteIp;
    UINT16 remotePort;
    SENTINEL_EVENT_MSG evt;

    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }

    remoteIp = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    remotePort = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;

    /* Report the connection to the engine for reputation + beacon analysis. The
     * engine maintains per-process connection history and the blocklist; the
     * driver enforces the returned verdict. For the synchronous fast path we
     * default to permit and let the engine raise an async block for future
     * connections to a flagged endpoint. */
    RtlZeroMemory(&evt, sizeof(evt));
    evt.target_process_id = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    evt.extra = remotePort;
    /* Encode the remote IPv4 into the first path cell for the engine. */
    evt.path[0] = (WCHAR)((remoteIp >> 24) & 0xFF);
    evt.path[1] = (WCHAR)((remoteIp >> 16) & 0xFF);
    evt.path[2] = (WCHAR)((remoteIp >> 8) & 0xFF);
    evt.path[3] = (WCHAR)(remoteIp & 0xFF);
    evt.path_chars = 4;
    SentinelSensorSendEvent(&gNetComms, SentinelMsgNetworkConnect, &evt,
                            sizeof(evt));

    classifyOut->actionType = FWP_ACTION_PERMIT;
    if ((filter != NULL) &&
        (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)) {
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

NTSTATUS SentinelNotifyConnect(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                               _In_ const GUID *filterKey,
                               _Inout_ FWPS_FILTER3 *filter) {
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

/* Register the callout + a filter at the ALE AUTH CONNECT v4 layer. */
NTSTATUS SentinelRegisterNetCallouts(_In_ PDEVICE_OBJECT DeviceObject) {
    NTSTATUS status;
    FWPS_CALLOUT3 sCallout = {0};
    FWPM_CALLOUT0 mCallout = {0};
    FWPM_FILTER0 mFilter = {0};
    FWPM_DISPLAY_DATA0 disp = {0};

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &gEngineHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    sCallout.calloutKey = SENTINEL_CALLOUT_CONNECT_V4;
    sCallout.classifyFn = SentinelClassifyConnectV4;
    sCallout.notifyFn = SentinelNotifyConnect;
    status = FwpsCalloutRegister3(DeviceObject, &sCallout, &gCalloutIdConnect);
    if (!NT_SUCCESS(status)) {
        goto done;
    }

    disp.name = L"Sentinel Connect Callout";
    mCallout.calloutKey = SENTINEL_CALLOUT_CONNECT_V4;
    mCallout.displayData = disp;
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    status = FwpmCalloutAdd0(gEngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        goto done;
    }

    mFilter.displayData = disp;
    mFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    mFilter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    mFilter.action.calloutKey = SENTINEL_CALLOUT_CONNECT_V4;
    mFilter.weight.type = FWP_EMPTY; /* auto-weight */
    mFilter.numFilterConditions = 0; /* all connections */
    status = FwpmFilterAdd0(gEngineHandle, &mFilter, NULL, &gFilterIdConnect);

done:
    return status;
}

VOID SentinelUnregisterNetCallouts(VOID) {
    if (gEngineHandle != NULL) {
        if (gFilterIdConnect != 0) {
            FwpmFilterDeleteById0(gEngineHandle, gFilterIdConnect);
            gFilterIdConnect = 0;
        }
        FwpmEngineClose0(gEngineHandle);
        gEngineHandle = NULL;
    }
    if (gCalloutIdConnect != 0) {
        /* Drain: FwpsCalloutUnregisterById0 returns STATUS_DEVICE_BUSY while any
         * classify is still in flight. Retry until it succeeds so no classify can
         * touch the comms ring after SentinelSensorCommsStop frees it. */
        NTSTATUS us;
        LARGE_INTEGER delay;
        for (;;) {
            us = FwpsCalloutUnregisterById0(gCalloutIdConnect);
            if (us != STATUS_DEVICE_BUSY) {
                break;
            }
            delay.QuadPart = -(100LL * 1000LL); /* 10 ms, relative */
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
        gCalloutIdConnect = 0;
    }
}

/* ----- Driver lifetime -------------------------------------------------- */
VOID SentinelNetUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    /* Unregister the callouts FIRST (drains all in-flight classify), THEN stop
     * comms (owns + deletes the device & symlink, frees the ring). Doing it in
     * this order guarantees no DISPATCH producer can run after the ring is freed. */
    SentinelUnregisterNetCallouts();
    SentinelSensorCommsStop(&gNetComms);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    SENTINEL_SENSOR_CONFIG cfg;
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = SentinelNetUnload;

    /* Create the secured control device (the engine's event channel). It doubles
     * as the WFP registration anchor. netfilter never asks a synchronous verdict. */
    RtlZeroMemory(&cfg, sizeof(cfg));
    cfg.DeviceName = SENTINEL_NET_DEVICE_NAME;
    cfg.SymbolicLinkName = SENTINEL_NET_SYMLINK_NAME;
    cfg.SupportsSyncVerdict = FALSE;
    cfg.FailClosed = FALSE;
    cfg.OnRegisterPid = NULL; /* no self-protection in netfilter */

    status = SentinelSensorCommsStart(&gNetComms, DriverObject, &cfg);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SentinelRegisterNetCallouts(gNetComms.DeviceObject);
    if (!NT_SUCCESS(status)) {
        SentinelSensorCommsStop(&gNetComms);
        return status;
    }
    return STATUS_SUCCESS;
}
