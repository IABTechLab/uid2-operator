package com.uid2.operator;

import com.uid2.operator.monitoring.IStatsCollectorQueue;
import com.uid2.operator.service.IUIDOperatorService;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.store.IClientKeyProvider;
import com.uid2.shared.store.IKeyAclProvider;
import com.uid2.shared.store.IKeyStore;
import com.uid2.shared.store.ISaltProvider;
import io.vertx.core.json.JsonObject;

import java.time.Clock;

//An extended UIDOperatorVerticle to expose classes for testing purposes
public class ExtendedUIDOperatorVerticle extends UIDOperatorVerticle {
    public ExtendedUIDOperatorVerticle(JsonObject config,
                                       IClientKeyProvider clientKeyProvider,
                                       IKeyStore keyStore,
                                       IKeyAclProvider keyAclProvider,
                                       ISaltProvider saltProvider,
                                       IOptOutStore optOutStore,
                                       Clock clock,
                                       IStatsCollectorQueue statsCollectorQueue) {
        super(config, clientKeyProvider, keyStore, keyAclProvider, saltProvider, optOutStore, clock, statsCollectorQueue);
    }

    public IUIDOperatorService getIdService() {
        return this.idService;
    }
}
