package com.uid2.operator.monitoring;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.uid2.operator.Const;
import com.uid2.operator.model.StatsCollectorMessageItem;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.eventbus.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.Temporal;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;


public class StatsCollectorVerticle extends AbstractVerticle implements IStatsCollectorQueue {
    private static final Logger LOGGER = LoggerFactory.getLogger(StatsCollectorVerticle.class);
    private HashMap<String, EndpointStat> pathMap;

    private static final int MAX_AVAILABLE = 1000;

    private final Duration jsonProcessingInterval;
    private Instant lastJsonProcessTime;

    private final Counter logCycleSkipperCounter;
    private final Counter domainMissedCounter;

    private final AtomicInteger _statsCollectorCount;
    private boolean _runningSerializer;

    private WorkerExecutor jsonSerializerExecutor;

    private final ObjectMapper mapper;
    private final Counter queueFullCounter;

    public StatsCollectorVerticle(long jsonIntervalMS) {
        pathMap = new HashMap<>();

        _statsCollectorCount = new AtomicInteger();
        _runningSerializer = false;

        jsonProcessingInterval = Duration.ofMillis(jsonIntervalMS);

        logCycleSkipperCounter = Counter
                .builder("uid2.api_usage_log_cycle_skipped")
                .description("counter for how many log cycles are skipped because the thread is still running")
                .register(Metrics.globalRegistry);

        domainMissedCounter = Counter
                .builder("uid2.api_usage_domain_missed")
                .description("counter for how many domains are missed because the dictionary is full")
                .register(Metrics.globalRegistry);
        queueFullCounter = Counter
                .builder("uid2.api_usage_queue_full")
                .description("counter for how many usage messages are dropped because the queue is full")
                .register(Metrics.globalRegistry);

        mapper = new ObjectMapper();
    }

    @Override
    public void start() throws Exception {
        super.start();
        this.jsonSerializerExecutor = vertx.createSharedWorkerExecutor("stats-collector-json-worker-pool");
        lastJsonProcessTime = (Instant) jsonProcessingInterval.addTo(Instant.now());
        vertx.eventBus().consumer(Const.Config.StatsCollectorEventBus, this::handleMessage);
    }

    public void handleMessage(Message message) {
        StatsCollectorMessageItem messageItem = null;
        try {
            messageItem = mapper.readValue(message.body().toString(), StatsCollectorMessageItem.class);
        } catch (JsonProcessingException e) {
            LOGGER.error(e.getMessage(), e);
            return;
        }

        assert messageItem != null;

        String path = messageItem.getPath();
        String apiVersion = "v0";
        String endpoint = path.substring(1);

        if(path.length() > 1 && path.charAt(1) == 'v') {
            int apiVIndex = path.indexOf("/", 1);
            apiVersion = path.substring(1, apiVIndex);
            endpoint = path.substring(apiVIndex+1);
        }

        String referer = messageItem.getReferer();
        if(referer == null){
            referer = "unknown";
        } else {
            try {
                referer = new URI(referer).getHost();
            } catch (URISyntaxException ignored) {
            }
        }
        String apiContact = messageItem.getApiContact();

        Integer siteId = messageItem.getSiteId();
        DomainStat domain = new DomainStat(referer, 1, apiContact);

        EndpointStat endpointStat = new EndpointStat(endpoint, siteId, apiVersion, domain);

        pathMap.merge(path, endpointStat, this::mergeEndpoint);

        _statsCollectorCount.decrementAndGet();

        if(Duration.between(lastJsonProcessTime, Instant.now()).compareTo(jsonProcessingInterval) >= 0){
            lastJsonProcessTime = Instant.now();
            if(_runningSerializer){
               logCycleSkipperCounter.increment();
            } else {
                _runningSerializer = true;
                Object[] stats = pathMap.values().toArray();
                this.jsonSerializerExecutor.<Void>executeBlocking(
                        promise -> promise.complete(this.serializeToLogs(stats)),
                        res -> {
                            if(!res.succeeded()) {
                                LOGGER.error("Failed To Serialize JSON");
                            }
                            _runningSerializer = false;
                        }
                );
                pathMap.clear();
            }

        }
    }

    Void serializeToLogs(Object[] stats) {
        LOGGER.debug("Starting JSON Serialize");
        ObjectMapper mapper = new ObjectMapper();
        for (int i = 0; i < stats.length; i++) {
            try {
                String jsonString = mapper.writeValueAsString(stats[i]);
                LOGGER.info(jsonString);
            } catch (JsonProcessingException e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
        return null;
    }

    private EndpointStat mergeEndpoint(EndpointStat a, EndpointStat b) {
        a.merge(b);
        return a;
    }


    public String getEndpointStats() {
        Object[] stats = pathMap.values().toArray();
        StringBuilder completeStats = new StringBuilder();
        for (int i = 0; i < stats.length; i++) {
            try {
                String jsonString = mapper.writeValueAsString(stats[i]);
                completeStats.append(jsonString).append("\n");
            } catch (JsonProcessingException e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
        return completeStats.toString();
    }

    @Override
    public void enqueue(Vertx sendersVertx, StatsCollectorMessageItem messageItem) {
        if (_statsCollectorCount.get() >= MAX_AVAILABLE) {
            queueFullCounter.increment();
            return;
        }

        try {
            vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));
            _statsCollectorCount.incrementAndGet();
        } catch (JsonProcessingException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    static class DomainStat {
        private final String domain;
        private Integer count;
        private final String apiContact;

        public DomainStat(String d, Integer c, String a) {
            domain = d;
            count = c;
            apiContact = a;
        }

        public String getDomain() {
            return domain;
        }

        public Integer getCount() {
            return count;
        }

        public String getApiContact() {
            return apiContact;
        }

        public void merge(DomainStat d) {
            count += d.getCount();
        }
    }

    class EndpointStat {
        private final String endpoint;
        private final Integer siteId;
        private final String apiVersion;
        private final ArrayList<DomainStat> domainList;
        private final HashMap<String, Integer> domainMap;

        private final int MaxDomains = 1000;

        public EndpointStat(String e, Integer s, String a, DomainStat d) {
            endpoint = e;
            siteId = s;
            apiVersion = a;
            domainList = new ArrayList<>(MaxDomains);
            domainMap = new HashMap<>();

            addDomain(d);
        }

        public String getEndpoint() {
            return endpoint;
        }

        public Integer getSiteId() {
            return siteId;
        }

        public String getApiVersion() {
            return apiVersion;
        }

        public ArrayList<DomainStat> getDomainList() {
            return domainList;
        }

        public void merge(EndpointStat other) {
            other.domainList.forEach(this::addDomain);
        }

        public void addDomain(DomainStat d) {
            String domainName = d.getDomain();
            if(domainMap.containsKey(domainName)) {
                domainList.get(domainMap.get(domainName)).merge(d);
            }
            else if(domainList.size() < MaxDomains) {
                domainList.add(d);
                domainMap.put(domainName, domainList.size()-1);
            } else {
                domainMissedCounter.increment();
            }
        }
    }
}


