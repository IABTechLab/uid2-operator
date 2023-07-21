package com.uid2.operator.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.uid2.shared.auth.Keyset;
import com.uid2.shared.auth.KeysetSnapshot;
import com.uid2.shared.model.KeysetKey;
import com.uid2.shared.store.IKeysetKeyStore;
import com.uid2.shared.store.reader.RotatingKeysetProvider;

public class KeyManager {
    private final IKeysetKeyStore keysetKeyStore;
    private final RotatingKeysetProvider keysetProvider;
    public KeyManager(IKeysetKeyStore keysetKeyStore, RotatingKeysetProvider keysetProvider) {
        this.keysetKeyStore = keysetKeyStore;
        this.keysetProvider = keysetProvider;
    }
    public KeysetKey getActiveKeyBySiteIdWithFallback(int siteId, int fallbackSiteId, Instant now) {
        KeysetKey key = getActiveKeyBySiteId(siteId, now);
        if (key == null) key = getActiveKeyBySiteId(fallbackSiteId, now);
        if (key == null) {
            throw new RuntimeException(String.format("Cannot get active key in default keyset with SITE ID %d or %d.", siteId, fallbackSiteId));
        }
        return key;
    }

    public KeysetKey getActiveKeyBySiteId(int siteId, Instant now) {
        IKeysetKeyStore.IkeysetKeyStoreSnapshot keysetKeyStoreSnapshot = this.keysetKeyStore.getSnapshot();
        KeysetSnapshot keysetSnapshot = this.keysetProvider.getSnapshot();

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