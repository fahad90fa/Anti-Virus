/*
 * Sentinel AV — Early Launch Anti-Malware (ELAM) boot driver.  [Phase 5]
 *
 * Windows lets a certified antivirus register an ELAM driver that loads BEFORE
 * every other boot-start driver. Our ELAM driver classifies each boot driver as
 * good, bad, or unknown, so a bootkit's malicious driver can be refused before it
 * ever runs. ELAM is the single most important piece for bootkit defense, and the
 * one with the steepest eligibility bar (Microsoft Virus Initiative + attestation
 * signing are mandatory to ship it).
 *
 * How it works:
 *   - DriverEntry registers a boot-driver callback (IoRegisterBootDriverCallback).
 *   - For each boot-start driver, the callback receives the image hash and the
 *     signer; we classify it against our measurements and the BYOVD blocklist
 *     (driverblock.c), returning a classification the boot loader honors.
 *   - We rely on (do not reinvent) Secure Boot and Trusted Boot for the earliest
 *     links; ELAM sits on top.
 *
 * Built with the WDK; requires an ELAM certificate and a registry resource
 * section with the malware-signature measurements. Test only in the VM.
 */
#include <ntddk.h>
#include <ntstrsafe.h>

/* From driverblock.c */
BOOLEAN SentinelIsDriverBlocked(const UCHAR *Sha256);
VOID SentinelDriverBlockInit(VOID);

PVOID gBootCallbackHandle = NULL;

/* Map our internal verdict to the Windows boot-driver classification. */
static BDCB_CLASSIFICATION SentinelClassify(const UCHAR *ImageHash) {
    if (ImageHash != NULL && SentinelIsDriverBlocked(ImageHash)) {
        /* Known-bad (BYOVD / blocklisted): refuse the load. */
        return BdCbClassificationKnownBadImage;
    }
    /* Unknown drivers are reported as "unknown"; boot policy (configurable by the
     * admin, default "good + unknown") decides whether unknown drivers load.
     * We never classify an unverified driver as KnownGood. */
    return BdCbClassificationUnknownImage;
}

/* Boot-driver callback invoked for each boot-start driver image. */
VOID SentinelBootDriverCallback(_In_ BDCB_CALLBACK_CLASSIFICATION Classification,
                                _Inout_ PBDCB_IMAGE_INFORMATION ImageInformation) {
    UNREFERENCED_PARAMETER(Classification);

    if (ImageInformation == NULL) {
        return;
    }

    if (Classification == BdCbClassifyImage) {
        /* ImageHash field carries the image hash the boot loader computed. */
        const UCHAR *hash = NULL;
        if (ImageInformation->ImageHash != NULL &&
            ImageInformation->ImageHashLength >= 32) {
            hash = (const UCHAR *)ImageInformation->ImageHash;
        }
        ImageInformation->Classification = SentinelClassify(hash);
    }
}

/* Status-update callback (boot start/end notifications). */
VOID SentinelBootStatusCallback(_In_ BDCB_STATUS_UPDATE_TYPE StatusType,
                                _In_ PVOID DriverEntryData) {
    UNREFERENCED_PARAMETER(StatusType);
    UNREFERENCED_PARAMETER(DriverEntryData);
    /* Hook point for recording the measured-boot timeline. No-op by default. */
}

/* The ELAM callback dispatcher routes classification vs status updates. */
VOID SentinelBootCallbackDispatch(
    _In_ PVOID CallbackContext,
    _In_ BDCB_CALLBACK_TYPE CallbackType,
    _In_ PVOID Data) {
    UNREFERENCED_PARAMETER(CallbackContext);
    switch (CallbackType) {
        case BdCbStatusUpdate:
            SentinelBootStatusCallback(
                ((PBDCB_STATUS_UPDATE)Data)->StatusUpdateType, Data);
            break;
        case BdCbInitializeImage:
            SentinelBootDriverCallback(BdCbClassifyImage,
                                       (PBDCB_IMAGE_INFORMATION)Data);
            break;
        default:
            break;
    }
}

VOID SentinelElamUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    if (gBootCallbackHandle != NULL) {
        IoUnRegisterBootDriverCallback(gBootCallbackHandle);
        gBootCallbackHandle = NULL;
    }
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = SentinelElamUnload;
    SentinelDriverBlockInit();

    gBootCallbackHandle =
        IoRegisterBootDriverCallback(SentinelBootCallbackDispatch, NULL);
    if (gBootCallbackHandle == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}
