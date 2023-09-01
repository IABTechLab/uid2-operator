package com.uid2.operator;

import com.uid2.operator.model.KeyManager;
import com.uid2.operator.monitoring.IStatsCollectorQueue;
import com.uid2.operator.service.IUIDOperatorService;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.store.IClientKeyProvider;
import com.uid2.shared.store.ISaltProvider;
import com.uid2.shared.store.IServiceLinkStore;
import com.uid2.shared.store.IServiceStore;
import io.vertx.core.json.JsonObject;

import java.time.Clock;

//An extended UIDOperatorVerticle to expose classes for testing purposes
public class ExtendedUIDOperatorVerticle extends UIDOperatorVerticle {
    public ExtendedUIDOperatorVerticle(JsonObject config,
                                       IClientKeyProvider clientKeyProvider,
                                       KeyManager keyManager,
                                       ISaltProvider saltProvider,
                                       IServiceStore serviceProvider,
                                       IServiceLinkStore serviceLinkProvider,
                                       IOptOutStore optOutStore,
                                       Clock clock,
                                       IStatsCollectorQueue statsCollectorQueue) {
        super(config, clientKeyProvider, keyManager, saltProvider, serviceProvider, serviceLinkProvider, optOutStore, clock, statsCollectorQueue);
    }

    public IUIDOperatorService getIdService() {
        return this.idService;
    }
}
