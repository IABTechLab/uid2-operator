package com.uid2.operator.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.auth.Keyset;
import com.uid2.shared.model.KeysetKey;
import com.uid2.shared.store.ACLMode.MissingAclMode;
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

    // Retrieve an active key from default keyset by caller's site id.
    public KeysetKey getActiveKeyBySiteId(int siteId, Instant now) {
        List<Keyset> keysets = this.keysetProvider.getSnapshot().getAllKeysets().values().stream()
                .filter(s -> s.isEnabled() && s.isDefault() && s.getSiteId() == siteId)
                .collect(Collectors.toList());
        if (keysets.isEmpty()) {
            return null;
        }
        if (keysets.size() > 1) {
            throw new IllegalArgumentException("Multiple default keysets are enabled with SITE ID " + siteId);
        }
        return getActiveKey(keysets.get(0).getKeysetId(), now);
    }

    public KeysetKey getActiveKey(int keysetId, Instant now) {
        return this.keysetKeyStore.getSnapshot().getActiveKey(keysetId, now);
    }

    public KeysetKey getKey(int keyId) {
        return this.keysetKeyStore.getSnapshot().getKey(keyId);
    }

    public List<KeysetKey> getActiveKeysetKeys() {
        return this.keysetKeyStore.getSnapshot().getActiveKeysetKeys();
    }

    public Keyset getKeyset(int keysetId) {
        return this.keysetProvider.getSnapshot().getKeyset(keysetId);
    }

    public Map<Integer, Keyset> getAllKeysets() {
        return this.keysetProvider.getSnapshot().getAllKeysets();
    }

    public Boolean canClientAccessKey(ClientKey clientKey, KeysetKey key, MissingAclMode mode) {
        return this.keysetProvider.getSnapshot().canClientAccessKey(clientKey, key, mode);
    }
}