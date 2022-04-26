package com.uid2.operator.monitoring;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.uid2.operator.model.StatsCollectorMessageItem;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.eventbus.Message;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;


public class StatsCollectorVerticle extends AbstractVerticle {
    private static final Logger LOGGER = LoggerFactory.getLogger(StatsCollectorVerticle.class);
    private HashMap<String, EndpointStat> pathMap;

    private static final int MAX_AVAILABLE = 1000;

    private final long jsonProcessingInterval;
    private Instant lastJsonProcessTime;

    private final Counter logCycleSkipperCounter;
    private final Counter domainMissedCounter;

    private final AtomicInteger _statsCollectorCount;
    private int _runningSerializer;

    private WorkerExecutor jsonSerializerExecutor;

    public StatsCollectorVerticle(long jsonIntervalMS, AtomicInteger statsCollectorCount) {
        pathMap = new HashMap<>();

        _statsCollectorCount = statsCollectorCount;
        _runningSerializer = 0;

        jsonProcessingInterval = jsonIntervalMS;
        lastJsonProcessTime = Instant.ofEpochMilli(Instant.now().toEpochMilli() + jsonIntervalMS - 1);

        logCycleSkipperCounter = Counter
                .builder("uid2.api_usage_log_cycle_skipped")
                .description("counter for how many log cycles are skipped because the thread is still running")
                .register(Metrics.globalRegistry);

        domainMissedCounter = Counter
                .builder("uid2.api_usage_domain_missed")
                .description("counter for how many domains are missed because the dictionary is full")
                .register(Metrics.globalRegistry);
    }

    @Override
    public void start() throws Exception {
        super.start();
        vertx.eventBus().consumer("StatsCollector", this::handleMessage);
        this.jsonSerializerExecutor = vertx.createSharedWorkerExecutor("stats-collector-json-worker-pool");
    }

    public void handleMessage(Message message) {
        ObjectMapper mapper = new ObjectMapper();
        StatsCollectorMessageItem messageItem = null;
        try {
            messageItem = mapper.readValue(message.body().toString(), StatsCollectorMessageItem.class);
        } catch (JsonProcessingException e) {
            LOGGER.error(e.getMessage(), e);
        }

        assert messageItem != null;

        String path = messageItem.getPath();
        String apiVersion = "v0";
        String endpoint = path.substring(1);

        if(path.charAt(1) == 'v') {
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
            } catch (URISyntaxException e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
        String apiContact = messageItem.getApiContact();

        Integer siteId = messageItem.getSiteId();
        DomainStat domain = new DomainStat(referer, 1, apiContact);

        EndpointStat endpointStat = new EndpointStat(endpoint, siteId, apiVersion, domain);

        pathMap.merge(path, endpointStat, this::mergeEndpoint);

        _statsCollectorCount.decrementAndGet();

        if(Duration.between(lastJsonProcessTime, Instant.now()).toMillis() >= jsonProcessingInterval){
            lastJsonProcessTime = Instant.now();
            if(_runningSerializer > 0){
               logCycleSkipperCounter.increment();
            } else {
                _runningSerializer ++;
                this.jsonSerializerExecutor.<String>executeBlocking(
                        promise -> promise.complete(this.serializeToLogs(pathMap.values().toArray())),
                        res -> {
                            if(res.succeeded()){
                                LOGGER.info(res.result());
                            } else {
                                LOGGER.error("Failed To Serialize JSON");
                            }
                            _runningSerializer--;
                        }
                );
                pathMap.clear();
            }

        }
    }

    public String serializeToLogs(Object[] stats) {
        LOGGER.debug("Starting JSON Serialize");
        ObjectMapper mapper = new ObjectMapper();
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

    private EndpointStat mergeEndpoint(EndpointStat a, EndpointStat b) {
        a.Merge(b);
        return a;
    }


    public String GetEndpointStats() {
        StringBuilder output = new StringBuilder();
        Object[] stats = pathMap.values().toArray();
        return serializeToLogs(stats);
    }

    public static class DomainStat {
        private String domain;
        private Integer count;
        private String apiContact;

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

        public String toString() {
            return "{Domain: " + domain + ", Count: " + count + ", Api_Contact: "+ apiContact + "}";
        }
    }

    class EndpointStat {
        private String endpoint;
        private Integer siteId;
        private String apiVersion;
        private ArrayList<DomainStat> domainList;
        private HashMap<String, Integer> domainMap;


        private final int DomainSize = 1000;

        public EndpointStat(String e, Integer s, String a, DomainStat d) {
            endpoint = e;
            siteId = s;
            apiVersion = a;
            domainList = new ArrayList<>(DomainSize);
            domainMap = new HashMap<>();

            AddDomain(d);
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

        public void Merge(EndpointStat other) {
            other.domainList.forEach(this::AddDomain);
        }

        public void AddDomain(DomainStat d) {
            String domainName = d.getDomain();
            if(domainMap.containsKey(domainName)) {
                domainList.get(domainMap.get(domainName)).merge(d);
            }
            else if(domainList.size() < DomainSize) {
                domainList.add(d);
                domainMap.put(domainName, domainList.size()-1);
            } else {
                domainMissedCounter.increment();
            }
        }

        public String toString() {
            StringBuilder outString = new StringBuilder("endpoint: " + endpoint + ", site_id: " + siteId + ", api_version: " + apiVersion +
                    "\nDomains: ");

            for (int i = 0; i < domainList.size(); i++) {
                outString.append(domainList.get(i).toString()).append(", ");
            }

            return outString.toString();
        }
    }
}


