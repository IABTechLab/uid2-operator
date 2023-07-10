package com.uid2.operator.monitoring;

import com.uid2.operator.service.EncryptionKeyUtil;
import com.uid2.shared.auth.KeysetSnapshot;
import com.uid2.shared.model.KeysetKey;
import com.uid2.shared.model.SaltEntry;
import com.uid2.shared.store.IKeysetKeyStore;
import com.uid2.shared.store.ISaltProvider;
import io.micrometer.core.instrument.Gauge;

import java.time.Instant;
import java.util.*;

import static io.micrometer.core.instrument.Metrics.globalRegistry;

public class OperatorMetrics {
    private Set<Integer> encryptionKeyGaugesBySiteId = new HashSet<>();
    private IKeysetKeyStore keysetKeyStore;
    private KeysetSnapshot keysetSnapshot;
    private ISaltProvider saltProvider;

    public OperatorMetrics(IKeysetKeyStore keysetKeyStore, KeysetSnapshot keysetSnapshot, ISaltProvider saltProvider) {
        this.keysetKeyStore = keysetKeyStore;
        this.keysetSnapshot = keysetSnapshot;
        this.saltProvider = saltProvider;
    }

    public void setup() {
        // salts
        Gauge
                .builder("uid2_second_level_salt_last_updated_max", () ->
                        Arrays.stream(saltProvider.getSnapshot(Instant.now()).getAllRotatingSalts())
                            .map(SaltEntry::getLastUpdated).max(Long::compare).orElse(null))
                .description("max last updated timestamp within currently effective second level salts")
                .register(globalRegistry);
        Gauge
                .builder("uid2_second_level_salt_last_updated_min", () ->
                        Arrays.stream(saltProvider.getSnapshot(Instant.now()).getAllRotatingSalts())
                            .map(SaltEntry::getLastUpdated).min(Long::compare).orElse(null))
                .description("max last updated timestamp within currently effective second level salts")
                .register(globalRegistry);

        update();
    }

    public void update() {
        keysetSnapshot.getAllKeysets().values().stream()
                .map(k -> k.getSiteId()).distinct()
                .filter(s -> !encryptionKeyGaugesBySiteId.contains(s))
                .forEachOrdered(siteId -> {
                    encryptionKeyGaugesBySiteId.add(siteId);
                    Gauge
                            .builder("uid2_encryption_key_activates", () -> {
                                final Instant now = Instant.now();
                                final KeysetKey key = EncryptionKeyUtil.getActiveKeyBySiteId(keysetKeyStore.getSnapshot(), keysetSnapshot, siteId, now);
                                return key == null ? null : key.getActivates().getEpochSecond();
                            })
                            .description("age of encryption keys by site id")
                            .tag("site_id", String.valueOf(siteId))
                            .register(globalRegistry);
                });
    }
}
