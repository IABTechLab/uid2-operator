package com.uid2.operator.service;

import com.uid2.shared.model.EncryptionKey;
import com.uid2.shared.store.IKeyStore;

import java.time.Instant;

public class EncryptionKeyUtil {
    public static EncryptionKey getActiveSiteKey(IKeyStore.IKeyStoreSnapshot keyStoreSnapshot, int siteId, int fallbackSiteId, Instant now) {
        EncryptionKey key = keyStoreSnapshot.getActiveSiteKey(siteId, now);
        if (key == null) key = keyStoreSnapshot.getActiveSiteKey(fallbackSiteId, now);
        if (key == null) {
            throw new RuntimeException(String.format("cannot get active site key with ID %d or %d", siteId, fallbackSiteId));
        }
        return key;
    }
}
