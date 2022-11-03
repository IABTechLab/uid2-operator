package com.uid2.operator.monitoring;

import com.uid2.shared.model.EncryptionKey;
import com.uid2.shared.model.SaltEntry;
import com.uid2.shared.store.IKeyStore;
import com.uid2.shared.store.ISaltProvider;
import io.micrometer.core.instrument.Gauge;

import java.time.Instant;
import java.util.*;

import static io.micrometer.core.instrument.Metrics.globalRegistry;

public class OperatorMetrics {
    private Set<Integer> encryptionKeyGaugesBySiteId = new HashSet<>();
    private IKeyStore keyStore;
    private ISaltProvider saltProvider;

    public OperatorMetrics(IKeyStore keyStore, ISaltProvider saltProvider) {
        this.keyStore = keyStore;
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
        keyStore.getSnapshot().getActiveKeySet().stream()
                .map(k -> k.getSiteId()).distinct()
                .filter(s -> !encryptionKeyGaugesBySiteId.contains(s))
                .forEachOrdered(siteId -> {
                    encryptionKeyGaugesBySiteId.add(siteId);
                    Gauge
                            .builder("uid2_encryption_key_activates", () -> {
                                final Instant now = Instant.now();
                                final EncryptionKey key = keyStore.getSnapshot().getActiveSiteKey(siteId, now);
                                return key == null ? null : key.getActivates().getEpochSecond();
                            })
                            .description("age of encryption keys by site id")
                            .tag("site_id", String.valueOf(siteId))
                            .register(globalRegistry);
                });
    }
}
