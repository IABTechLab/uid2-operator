package com.uid2.operator.service;

import com.uid2.shared.auth.Keyset;
import com.uid2.shared.auth.KeysetSnapshot;
import com.uid2.shared.model.KeysetKey;
import com.uid2.shared.store.IKeysetKeyStore;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class EncryptionKeyUtil {
    public static KeysetKey getActiveKeyBySiteIdWithFallback(IKeysetKeyStore.IkeysetKeyStoreSnapshot keysetKeyStoreSnapshot, KeysetSnapshot keysetSnapshot, int siteId, int fallbackSiteId, Instant now) {
        KeysetKey key = getActiveKeyBySiteId(keysetKeyStoreSnapshot, keysetSnapshot, siteId, now);
        if (key == null) key = getActiveKeyBySiteId(keysetKeyStoreSnapshot, keysetSnapshot, fallbackSiteId, now);
        if (key == null) {
            throw new RuntimeException(String.format("Cannot get active key in default keyset with SITE ID %d or %d.", siteId, fallbackSiteId));
        }
        return key;
    }

    public static KeysetKey getActiveKeyBySiteId(IKeysetKeyStore.IkeysetKeyStoreSnapshot keysetKeyStoreSnapshot, KeysetSnapshot keysetSnapshot, int siteId, Instant now) {
        //keyManager.getActiveKeyBySiteId(site id, now)
        Map<Integer, Keyset> keysetMap = keysetSnapshot.getAllKeysets();

        // ID_READER can get null keyset
        if (keysetMap == null) return null;

        List<Keyset> keysets = keysetMap.values().stream()
            .filter(s -> s.getSiteId() == siteId && s.isDefault() && s.isEnabled())
            .collect(Collectors.toList());

        if (keysets.size() > 1) {
            throw new RuntimeException(String.format("Multiple default keysets are enabled with SITE ID %d.", siteId));
        }

        Keyset defaultKeyset = !keysets.isEmpty() ? keysets.get(0) : null;
        if (defaultKeyset == null) {
            return null;
        }

        KeysetKey activeKey = keysetKeyStoreSnapshot.getActiveKey(defaultKeyset.getKeysetId(), now);
        return activeKey;
    }
}