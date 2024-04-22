package com.uid2.operator;

import com.uid2.operator.model.KeyManager;
import com.uid2.operator.monitoring.IStatsCollectorQueue;
import com.uid2.operator.service.IUIDOperatorService;
import com.uid2.operator.service.SecureLinkValidatorService;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.store.*;
import io.vertx.core.json.JsonObject;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

//An extended UIDOperatorVerticle to expose classes for testing purposes
public class ExtendedUIDOperatorVerticle extends UIDOperatorVerticle {
    public ExtendedUIDOperatorVerticle(JsonObject config,
                                       boolean clientSideTokenGenerate,
                                       ISiteStore siteProvider,
                                       IClientKeyProvider clientKeyProvider,
                                       IClientSideKeypairStore clientSideKeypairProvider,
                                       KeyManager keyManager,
                                       ISaltProvider saltProvider,
                                       IOptOutStore optOutStore,
                                       Clock clock,
                                       IStatsCollectorQueue statsCollectorQueue,
                                       SecureLinkValidatorService secureLinkValidationService) {
        super(config, clientSideTokenGenerate, siteProvider, clientKeyProvider, clientSideKeypairProvider, keyManager, saltProvider, optOutStore, clock, statsCollectorQueue, secureLinkValidationService);
    }

    public IUIDOperatorService getIdService() {
        return this.idService;
    }

    public void setKeySharingEndpointProvideSiteDomainNames(boolean enable) {
        this.keySharingEndpointProvideSiteDomainNames = enable;
    }

    public void setMaxSharingLifetimeSeconds(int maxSharingLifetimeSeconds) {
        this.maxSharingLifetimeSeconds = maxSharingLifetimeSeconds;
    }

    public void setLastInvalidOriginProcessTime(Instant lastInvalidOriginProcessTime) {
        this.lastInvalidOriginProcessTime = lastInvalidOriginProcessTime;
    }

    public void setSiteIdToInvalidOriginsAndAppNames(Map<Integer, Set<String>> siteIdToInvalidOriginsAndAppNames) {
        this.siteIdToInvalidOriginsAndAppNames = siteIdToInvalidOriginsAndAppNames;
    }
}
