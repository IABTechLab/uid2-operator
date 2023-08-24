package com.uid2.operator.monitoring;

import com.uid2.operator.model.KeyManager;
import com.uid2.shared.model.KeysetKey;
import com.uid2.shared.model.SaltEntry;
import com.uid2.shared.store.ISaltProvider;
import io.micrometer.core.instrument.Gauge;

import java.time.Instant;
import java.util.*;

import static io.micrometer.core.instrument.Metrics.globalRegistry;

public class OperatorMetrics {
    private Set<Integer> encryptionKeyGaugesBySiteId = new HashSet<>();
    private ISaltProvider saltProvider;
    private KeyManager keyManager;

    public OperatorMetrics(KeyManager keyManager, ISaltProvider saltProvider) {
        this.keyManager = keyManager;
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
        keyManager.getAllKeysets().values().stream()
                .map(k -> k.getSiteId()).distinct()
                .filter(s -> !encryptionKeyGaugesBySiteId.contains(s))
                .forEachOrdered(siteId -> {
                    encryptionKeyGaugesBySiteId.add(siteId);
                    Gauge
                            .builder("uid2_encryption_key_activates", () -> {
                                final Instant now = Instant.now();
                                final KeysetKey key = keyManager.getActiveKeyBySiteId(siteId, now);
                                return key == null ? null : key.getActivates().getEpochSecond();
                            })
                            .description("age of encryption keys by site id")
                            .tag("site_id", String.valueOf(siteId))
                            .register(globalRegistry);
                });
    }
}
