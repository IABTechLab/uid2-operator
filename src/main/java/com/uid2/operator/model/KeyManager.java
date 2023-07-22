package com.uid2.operator.model;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

import com.uid2.shared.auth.Keyset;
import com.uid2.shared.auth.KeysetSnapshot;
import com.uid2.shared.model.KeysetKey;
import com.uid2.shared.store.IKeysetKeyStore;
import com.uid2.shared.store.reader.RotatingKeysetProvider;

public class KeyManager {
    private final IKeysetKeyStore.IkeysetKeyStoreSnapshot keysetKeyStoreSnapshot;
    private final KeysetSnapshot keysetSnapshot;
    public KeyManager(IKeysetKeyStore keysetKeyStore, RotatingKeysetProvider keysetProvider) {
        this.keysetKeyStoreSnapshot = keysetKeyStore.getSnapshot();
        this.keysetSnapshot = keysetProvider.getSnapshot();
    }
    public KeysetKey getActiveKeyBySiteIdWithFallback(int siteId, int fallbackSiteId, Instant now) {
        KeysetKey key = getActiveKeyBySiteId(siteId, now);
        if (key == null) key = getActiveKeyBySiteId(fallbackSiteId, now);
        if (key == null) {
            throw new RuntimeException(String.format("Cannot get active key in default keyset with SITE ID %d or %d.", siteId, fallbackSiteId));
        }
        return key;
    }

    // Retrieve an active key from default keyset by caller's site id.
    public KeysetKey getActiveKeyBySiteId(int siteId, Instant now) {

        List<Keyset> keysets = keysetSnapshot.getAllKeysets().values().stream()
                .filter(s -> s.isEnabled() && s.isDefault() && s.getSiteId() == siteId)
                .collect(Collectors.toList());

        if (keysets.size() != 1) {
            if (keysets.isEmpty()) {
                throw new IllegalArgumentException("Cannot get active key in default keyset with SITE ID " + siteId);
            } else {
                throw new IllegalArgumentException("Multiple default keysets are enabled with SITE ID " + siteId);
            }
        }

        KeysetKey activeKey = keysetKeyStoreSnapshot.getActiveKey(keysets.get(0).getKeysetId(), now);
        return activeKey;
    }

    public KeysetKey getActiveKey(int keysetId, Instant now) {
        return keysetKeyStoreSnapshot.getActiveKey(keysetId, now);
    }
}