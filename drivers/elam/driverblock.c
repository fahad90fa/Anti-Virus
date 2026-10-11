/*
 * Sentinel AV — BYOVD vulnerable-driver blocklist.  [Phase 5]
 *
 * The most common way serious attackers reach the kernel today is not writing a
 * rootkit from scratch but loading a legitimately signed BUT vulnerable driver
 * and exploiting its bug (Bring Your Own Vulnerable Driver). This module holds a
 * blocklist of hashes of known-abusable signed drivers and refuses their load,
 * mirroring Microsoft's own vulnerable-driver blocklist and extending it. It is
 * consulted both from the ELAM boot-driver classification (below) and from the
 * image-load callback in procmon for runtime driver loads.
 *
 * The authoritative list is delivered via the signed update pipeline; a small
 * built-in seed set ships in the driver so protection exists before the first
 * update. Hashes here are SHA-256 of the driver image.
 *
 * Built with the WDK; kernel-mode C.
 */
#include <ntddk.h>

#define SENTINEL_DRIVERBLOCK_HASH_LEN 32

typedef struct _SENTINEL_BLOCKED_DRIVER {
    UCHAR Sha256[SENTINEL_DRIVERBLOCK_HASH_LEN];
    const char *Name;
} SENTINEL_BLOCKED_DRIVER;

/* Built-in seed set. Zero-filled placeholders here; real hashes are provisioned
 * via the signed update pipeline and merged at load. The structure and lookup
 * are the point — the content is data, delivered out of band. */
static const SENTINEL_BLOCKED_DRIVER gBuiltinBlocklist[] = {
    { {0}, "placeholder-seed" },
};
static const ULONG gBuiltinBlocklistCount =
    sizeof(gBuiltinBlocklist) / sizeof(gBuiltinBlocklist[0]);

/* Dynamically-loaded (updated) blocklist, allocated from paged pool at update
 * time. Guarded by gBlocklistLock. */
static SENTINEL_BLOCKED_DRIVER *gDynamicBlocklist = NULL;
static ULONG gDynamicBlocklistCount = 0;
static FAST_MUTEX gBlocklistLock;
static BOOLEAN gBlocklistInit = FALSE;

VOID SentinelDriverBlockInit(VOID) {
    if (!gBlocklistInit) {
        ExInitializeFastMutex(&gBlocklistLock);
        gBlocklistInit = TRUE;
    }
}

static BOOLEAN HashEquals(const UCHAR *a, const UCHAR *b) {
    ULONG i;
    UCHAR diff = 0;
    /* Constant-time compare to avoid leaking match position. */
    for (i = 0; i < SENTINEL_DRIVERBLOCK_HASH_LEN; ++i) {
        diff |= (UCHAR)(a[i] ^ b[i]);
    }
    return diff == 0;
}

/* Returns TRUE if the given driver image hash is on the blocklist (load refused).
 * A hash of all zeros never matches (placeholder guard). */
BOOLEAN SentinelIsDriverBlocked(_In_reads_bytes_(SENTINEL_DRIVERBLOCK_HASH_LEN)
                                const UCHAR *Sha256) {
    ULONG i;
    UCHAR zero[SENTINEL_DRIVERBLOCK_HASH_LEN] = {0};
    BOOLEAN blocked = FALSE;

    if (Sha256 == NULL || HashEquals(Sha256, zero)) {
        return FALSE;
    }

    for (i = 0; i < gBuiltinBlocklistCount; ++i) {
        if (HashEquals(gBuiltinBlocklist[i].Sha256, Sha256)) {
            return TRUE;
        }
    }

    if (gBlocklistInit) {
        ExAcquireFastMutex(&gBlocklistLock);
        for (i = 0; i < gDynamicBlocklistCount; ++i) {
            if (HashEquals(gDynamicBlocklist[i].Sha256, Sha256)) {
                blocked = TRUE;
                break;
            }
        }
        ExReleaseFastMutex(&gBlocklistLock);
    }
    return blocked;
}

/* Replace the dynamic blocklist with an updated set (called when the engine
 * pushes a verified signature update). Takes ownership of Entries (paged pool). */
NTSTATUS SentinelDriverBlockUpdate(_In_opt_ SENTINEL_BLOCKED_DRIVER *Entries,
                                   _In_ ULONG Count) {
    SENTINEL_BLOCKED_DRIVER *old;
    ULONG oldCount;

    if (!gBlocklistInit) {
        SentinelDriverBlockInit();
    }
    ExAcquireFastMutex(&gBlocklistLock);
    old = gDynamicBlocklist;
    oldCount = gDynamicBlocklistCount;
    gDynamicBlocklist = Entries;
    gDynamicBlocklistCount = Count;
    ExReleaseFastMutex(&gBlocklistLock);

    UNREFERENCED_PARAMETER(oldCount);
    if (old != NULL) {
        ExFreePool(old);
    }
    return STATUS_SUCCESS;
}
