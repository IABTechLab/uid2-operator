package com.uid2.operator;

import com.uid2.operator.model.KeyManager;
import com.uid2.operator.monitoring.IStatsCollectorQueue;
import com.uid2.operator.service.IUIDOperatorService;
import com.uid2.operator.service.SecureLinkValidatorService;
import com.uid2.operator.store.IConfigStore;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.store.*;
import com.uid2.shared.store.salt.ISaltProvider;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

//An extended UIDOperatorVerticle to expose classes for testing purposes
public class ExtendedUIDOperatorVerticle extends UIDOperatorVerticle {
    public ExtendedUIDOperatorVerticle(IConfigStore configStore,
                                       JsonObject config,
                                       boolean clientSideTokenGenerate,
                                       ISiteStore siteProvider,
                                       IClientKeyProvider clientKeyProvider,
                                       IClientSideKeypairStore clientSideKeypairProvider,
                                       KeyManager keyManager,
                                       ISaltProvider saltProvider,
                                       IOptOutStore optOutStore,
                                       Clock clock,
                                       IStatsCollectorQueue statsCollectorQueue,
                                       SecureLinkValidatorService secureLinkValidationService,
                                       Handler<Boolean> saltRetrievalResponseHandler) {
        super(configStore, config, clientSideTokenGenerate, siteProvider, clientKeyProvider, clientSideKeypairProvider, keyManager, saltProvider, optOutStore, clock, statsCollectorQueue, secureLinkValidationService, saltRetrievalResponseHandler);
    }

    public IUIDOperatorService getIdService() {
        return this.idService;
    }

    public void setKeySharingEndpointProvideAppNames(boolean enable) {
        this.keySharingEndpointProvideAppNames = enable;
    }

    public void setLastInvalidOriginProcessTime(Instant lastInvalidOriginProcessTime) {
        this.lastInvalidOriginProcessTime = lastInvalidOriginProcessTime;
    }

    public void setSiteIdToInvalidOriginsAndAppNames(Map<Integer, Set<String>> siteIdToInvalidOriginsAndAppNames) {
        this.siteIdToInvalidOriginsAndAppNames = siteIdToInvalidOriginsAndAppNames;
    }
}
