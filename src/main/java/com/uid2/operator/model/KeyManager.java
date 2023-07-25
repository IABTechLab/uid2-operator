package com.uid2.operator.model;

import com.uid2.operator.Const;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.auth.Keyset;
import com.uid2.shared.model.KeysetKey;
import com.uid2.shared.store.ACLMode.MissingAclMode;
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

    public KeysetKey getActiveKeyBySiteIdWithFallback(int siteId, int fallbackSiteId, Instant asOf) {
        KeysetKey key = getActiveKeyBySiteId(siteId, asOf);
        if (key == null) key = getActiveKeyBySiteId(fallbackSiteId, asOf);
        if (key == null) {
            String error = String.format("Cannot get active key in default keyset with SITE ID %d or %d.", siteId, fallbackSiteId);
            LOGGER.error(error);
            throw new IllegalArgumentException(error);
        }
        return key;
    }

    // Retrieve an active key from default keyset by caller's site id.
    public KeysetKey getActiveKeyBySiteId(int siteId, Instant asOf) {
        List<Keyset> keysets = this.keysetProvider.getSnapshot().getAllKeysets().values().stream()
                .filter(s -> s.isEnabled() && s.isDefault() && s.getSiteId() == siteId)
                .collect(Collectors.toList());
        if (keysets.isEmpty()) {
            LOGGER.warn(String.format("Cannot get a default keyset with SITE ID %d.", siteId));
            return null;
        }
        if (keysets.size() > 1) {
            String error = String.format("Multiple default keysets are enabled with SITE ID %d.", siteId);
            LOGGER.error(error);
            throw new IllegalArgumentException(error);
        }
        return getActiveKey(keysets.get(0).getKeysetId(), asOf);
    }

    public KeysetKey getActiveKey(int keysetId, Instant now) {
        return this.keysetKeyStore.getSnapshot().getActiveKey(keysetId, now);
    }

    public KeysetKey getKey(int keyId) {
        return this.keysetKeyStore.getSnapshot().getKey(keyId);
    }

    private List<KeysetKey> getActiveKeysetKeys() {
        // return all keys without expiry check
        return this.keysetKeyStore.getSnapshot().getActiveKeysetKeys();
    }

    public List<KeysetKey> getKeysetKeys() {
        Map<Integer, Keyset> keysetMap = this.keysetProvider.getSnapshot().getAllKeysets();
        List<KeysetKey> keys = getActiveKeysetKeys();
        return keys
                .stream().filter(k -> keysetMap.containsKey(k.getKeysetId()) && k.getKeysetId() != Const.Config.RefreshKeyKeysetId)
                .sorted(Comparator.comparing(KeysetKey::getId)).collect(Collectors.toList());
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

    public KeysetKey getMasterKey() {
        return getMasterKey(Instant.now());
    }
    public KeysetKey getMasterKey(Instant asOf) {
        KeysetKey key = this.keysetKeyStore.getSnapshot().getActiveKey(Const.Config.MasterKeyKeysetId, asOf);
        if (key == null) {
            throw new RuntimeException(String.format("Cannot get a master key with keyset ID %d.", Const.Config.MasterKeyKeysetId));
        }
        return key;
    }

    public KeysetKey getPublisherKey() {
        return getPublisherKey(Instant.now());
    }

    public KeysetKey getPublisherKey(Instant asOf) {
        KeysetKey key = this.keysetKeyStore.getSnapshot().getActiveKey(Const.Config.PublisherKeyKeysetId, asOf);
        if (key == null) {
            throw new RuntimeException(String.format("Cannot get a publisher key with keyset ID %d.", Const.Config.PublisherKeyKeysetId));
        }
        return key;
    }

    public KeysetKey getRefreshKey() {
        return getRefreshKey(Instant.now());
    }

    public KeysetKey getRefreshKey(Instant asOf) {
        KeysetKey key = this.keysetKeyStore.getSnapshot().getActiveKey(Const.Config.RefreshKeyKeysetId, asOf);
        if (key == null) {
            throw new RuntimeException(String.format("Cannot get a refresh key with keyset ID %d.", Const.Config.RefreshKeyKeysetId));
        }
        return key;
    }
}