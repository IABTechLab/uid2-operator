// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

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
