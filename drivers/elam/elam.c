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

/* The ELAM boot-driver callback. Signature per PBOOT_DRIVER_CALLBACK_FUNCTION:
 *   (PVOID CallbackContext, BDCB_CALLBACK_TYPE Classification, PVOID ImageInformation)
 * For BdCbInitializeImage, ImageInformation points to a BDCB_IMAGE_INFORMATION
 * we classify (good/bad/unknown); BdCbStatusUpdate is a boot-progress
 * notification we do not act on. */
VOID SentinelBootCallbackDispatch(
    _In_ PVOID CallbackContext,
    _In_ BDCB_CALLBACK_TYPE Classification,
    _In_ PVOID ImageInformation) {
    UNREFERENCED_PARAMETER(CallbackContext);

    if (Classification == BdCbInitializeImage && ImageInformation != NULL) {
        PBDCB_IMAGE_INFORMATION info = (PBDCB_IMAGE_INFORMATION)ImageInformation;
        /* ImageHash carries the image hash the boot loader computed. */
        const UCHAR *hash = NULL;
        if (info->ImageHash != NULL && info->ImageHashLength >= 32) {
            hash = (const UCHAR *)info->ImageHash;
        }
        info->Classification = SentinelClassify(hash);
    }
    /* BdCbStatusUpdate: boot-progress notification; nothing to do. */
}

VOID SentinelElamUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    if (gBootCallbackHandle != NULL) {
        IoUnregisterBootDriverCallback(gBootCallbackHandle);
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
