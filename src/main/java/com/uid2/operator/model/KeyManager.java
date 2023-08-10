package com.uid2.operator.model;

import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.Const;
import com.uid2.shared.auth.Keyset;
import com.uid2.shared.model.KeysetKey;
import com.uid2.shared.store.IKeysetKeyStore;
import com.uid2.shared.store.reader.RotatingKeysetProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class KeyManager {
    private static final Logger LOGGER = LoggerFactory.getLogger(UIDOperatorVerticle.class);
    private final IKeysetKeyStore keysetKeyStore;
    private final RotatingKeysetProvider keysetProvider;

    public KeyManager(IKeysetKeyStore keysetKeyStore, RotatingKeysetProvider keysetProvider) {
        this.keysetKeyStore = keysetKeyStore;
        this.keysetProvider = keysetProvider;
    }

    public KeyManagerSnapshot getKeyManagerSnapshot(int siteId) {
        return new KeyManagerSnapshot(
                this.keysetProvider.getSnapshot(),
                this.getAllKeysets(),
                this.getKeysForSharingOrDsps(),
                this.getMasterKey(),
                this.getDefaultKeysetBySiteId(siteId));
    }

    public KeysetKey getActiveKeyBySiteIdWithFallback(int siteId, int fallbackSiteId, Instant asOf) {
        KeysetKey key = getActiveKeyBySiteId(siteId, asOf);
        if (key == null) key = getActiveKeyBySiteId(fallbackSiteId, asOf);
        if (key == null) {
            throw new IllegalArgumentException(String.format("Cannot get active key in default keyset with SITE ID %d or %d.", siteId, fallbackSiteId));
        }
        return key;
    }

    private Keyset getDefaultKeysetBySiteId(int siteId) {
        List<Keyset> keysets = this.keysetProvider.getSnapshot().getAllKeysets().values().stream()
                .filter(s -> s.isEnabled() && s.isDefault() && s.getSiteId() == siteId).collect(Collectors.toList());
        if (keysets.isEmpty()) {
            LOGGER.warn(String.format("Cannot get a default keyset with SITE ID %d.", siteId));
            return null;
        }

        if (keysets.size() > 1) {
            throw new IllegalArgumentException(String.format("Multiple default keysets are enabled with SITE ID %d.", siteId));
        }

        return keysets.get(0);
    }

    // Retrieve an key from default keyset by caller's site id.
    public KeysetKey getActiveKeyBySiteId(int siteId, Instant asOf) {
        Keyset keyset = getDefaultKeysetBySiteId(siteId);
        if (keyset == null) {
            return null;
        }

        return getActiveKey(keyset.getKeysetId(), asOf);
    }

    private KeysetKey getActiveKey(int keysetId, Instant asOf) {
        return this.keysetKeyStore.getSnapshot().getActiveKey(keysetId, asOf);
    }

    public KeysetKey getKey(int keyId) {
        return this.keysetKeyStore.getSnapshot().getKey(keyId);
    }


    public List<KeysetKey> getKeysForSharingOrDsps() {
        Map<Integer, Keyset> keysetMap = this.keysetProvider.getSnapshot().getAllKeysets();
        List<KeysetKey> keys = keysetKeyStore.getSnapshot().getActiveKeysetKeys(); //getActiveKeysetKeys() is incorrectly named, as this includes expired keys
        return keys
                .stream().filter(k -> keysetMap.containsKey(k.getKeysetId()) && k.getKeysetId() != Const.Data.RefreshKeysetId)
                .sorted(Comparator.comparing(KeysetKey::getId)).collect(Collectors.toList());
    }

    public int getSiteIdFromKeyId(int keyId) {
        KeysetKey key = getKey(keyId);
        Keyset keyset = getKeyset(key.getKeysetId());
        return keyset.getSiteId();

    }

    private Keyset getKeyset(int keysetId) {
        return this.keysetProvider.getSnapshot().getKeyset(keysetId);
    }

    public Map<Integer, Keyset> getAllKeysets() {
        return this.keysetProvider.getSnapshot().getAllKeysets();
    }

    public KeysetKey getMasterKey() {
        return getMasterKey(Instant.now());
    }
    public KeysetKey getMasterKey(Instant asOf) {
        KeysetKey key = this.keysetKeyStore.getSnapshot().getActiveKey(Const.Data.MasterKeysetId, asOf);
        if (key == null) {
            throw new RuntimeException(String.format("Cannot get a master key with keyset ID %d.", Const.Data.MasterKeysetId));
        }
        return key;
    }

    public KeysetKey getRefreshKey() {
        return getRefreshKey(Instant.now());
    }

    public KeysetKey getRefreshKey(Instant asOf) {
        KeysetKey key = this.keysetKeyStore.getSnapshot().getActiveKey(Const.Data.RefreshKeysetId, asOf);
        if (key == null) {
            throw new RuntimeException(String.format("Cannot get a refresh key with keyset ID %d.", Const.Data.RefreshKeysetId));
        }
        return key;
    }
}
