package com.uid2.operator.model;

import com.uid2.shared.auth.Keyset;
import com.uid2.shared.auth.KeysetSnapshot;
import com.uid2.shared.model.KeysetKey;

import java.util.List;
import java.util.Map;

public class KeyManagerSnapshot {
    private final KeysetSnapshot keysetSnapshot;
    private final Map<Integer, Keyset> keysetMap;
    private final List<KeysetKey> keysetKeys;
    private final KeysetKey masterKey;
    private final Keyset defaultKeyset;

    KeyManagerSnapshot(KeysetSnapshot keysetSnapshot, Map<Integer, Keyset> keysetMap, List<KeysetKey> keysetKeys, KeysetKey masterKey, Keyset defaultKeyset) {
        this.keysetSnapshot = keysetSnapshot;
        this.keysetMap = keysetMap;
        this.keysetKeys = keysetKeys;
        this.masterKey = masterKey;
        this.defaultKeyset = defaultKeyset;
    }

    public Map<Integer, Keyset> getAllKeysets() {
        return this.keysetMap;
    }

    public List<KeysetKey> getKeysetKeys() {
        return this.keysetKeys;
    }

    public KeysetKey getMasterKey() {
        return this.masterKey;
    }

    public Keyset getDefaultKeyset() {
        return this.defaultKeyset;
    }

    public KeysetSnapshot getKeysetSnapshot() {
        return this.keysetSnapshot;
    }
}
