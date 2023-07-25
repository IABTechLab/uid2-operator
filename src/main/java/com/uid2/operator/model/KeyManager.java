package com.uid2.operator.model;

import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.Const;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.auth.Keyset;
import com.uid2.shared.auth.KeysetSnapshot;
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
    private final Boolean snapshotMode;
    private final IKeysetKeyStore.IkeysetKeyStoreSnapshot keysetKeyStoreSnapshot;
    private final KeysetSnapshot keysetSnapshot;

    public KeyManager(IKeysetKeyStore keysetKeyStore, RotatingKeysetProvider keysetProvider) {
        this.keysetKeyStore = keysetKeyStore;
        this.keysetProvider = keysetProvider;
        this.snapshotMode = false;
        this.keysetKeyStoreSnapshot = null;
        this.keysetSnapshot = null;
    }

    private KeyManager(IKeysetKeyStore keysetKeyStore, RotatingKeysetProvider keysetProvider, Boolean snapshotMode) {
        this.keysetKeyStore = keysetKeyStore;
        this.keysetProvider = keysetProvider;
        this.snapshotMode = snapshotMode;
        this.keysetKeyStoreSnapshot = snapshotMode ? this.keysetKeyStore.getSnapshot() : null;
        this.keysetSnapshot = snapshotMode ? this.keysetProvider.getSnapshot() : null;
    }

    public KeyManager getSnapshot() {
        return new KeyManager(this.keysetKeyStore, this.keysetProvider, true);
    }

    private IKeysetKeyStore.IkeysetKeyStoreSnapshot getKeysetKeyStoreSnapshot() {
        return snapshotMode ? this.keysetKeyStoreSnapshot : this.keysetKeyStore.getSnapshot();
    }

    private KeysetSnapshot getKeysetSnapshot() {
        return snapshotMode ? this.keysetSnapshot : this.keysetProvider.getSnapshot();
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
        List<Keyset> keysets = getKeysetSnapshot().getAllKeysets().values().stream()
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

    public KeysetKey getActiveKey(int keysetId) {
        return getActiveKey(keysetId, Instant.now());
    }
    private KeysetKey getActiveKey(int keysetId, Instant asOf) {
        return getKeysetKeyStoreSnapshot().getActiveKey(keysetId, asOf);
    }

    public KeysetKey getKey(int keyId) {
        return getKeysetKeyStoreSnapshot().getKey(keyId);
    }

    private List<KeysetKey> getActiveKeysetKeys() {
        // return all keys without expiry check
        return getKeysetKeyStoreSnapshot().getActiveKeysetKeys();
    }

    public List<KeysetKey> getKeysetKeys() {
        Map<Integer, Keyset> keysetMap = getKeysetSnapshot().getAllKeysets();
        List<KeysetKey> keys = getActiveKeysetKeys();
        return keys
                .stream().filter(k -> keysetMap.containsKey(k.getKeysetId()) && k.getKeysetId() != Const.Data.RefreshKeysetId)
                .sorted(Comparator.comparing(KeysetKey::getId)).collect(Collectors.toList());
    }

    public Keyset getKeyset(int keysetId) {
        return getKeysetSnapshot().getKeyset(keysetId);
    }

    public Map<Integer, Keyset> getAllKeysets() {
        return getKeysetSnapshot().getAllKeysets();
    }

    public Boolean canClientAccessKey(ClientKey clientKey, KeysetKey key, MissingAclMode mode) {
        return getKeysetSnapshot().canClientAccessKey(clientKey, key, mode);
    }

    public KeysetKey getMasterKey() {
        return getMasterKey(Instant.now());
    }
    public KeysetKey getMasterKey(Instant asOf) {
        KeysetKey key = getKeysetKeyStoreSnapshot().getActiveKey(Const.Data.MasterKeysetId, asOf);
        if (key == null) {
            throw new RuntimeException(String.format("Cannot get a master key with keyset ID %d.", Const.Data.MasterKeysetId));
        }
        return key;
    }

    public KeysetKey getPublisherKey() {
        return getPublisherKey(Instant.now());
    }

    public KeysetKey getPublisherKey(Instant asOf) {
        KeysetKey key = getKeysetKeyStoreSnapshot().getActiveKey(Const.Data.FallbackPublisherKeysetId, asOf);
        if (key == null) {
            throw new RuntimeException(String.format("Cannot get a publisher key with keyset ID %d.", Const.Data.FallbackPublisherKeysetId));
        }
        return key;
    }

    public KeysetKey getRefreshKey() {
        return getRefreshKey(Instant.now());
    }

    public KeysetKey getRefreshKey(Instant asOf) {
        KeysetKey key = getKeysetKeyStoreSnapshot().getActiveKey(Const.Data.RefreshKeysetId, asOf);
        if (key == null) {
            throw new RuntimeException(String.format("Cannot get a refresh key with keyset ID %d.", Const.Data.RefreshKeysetId));
        }
        return key;
    }
}