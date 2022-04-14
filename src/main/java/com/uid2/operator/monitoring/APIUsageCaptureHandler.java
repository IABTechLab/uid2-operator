package com.uid2.operator.monitoring;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.middleware.AuthMiddleware;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.Message;
import io.vertx.core.eventbus.MessageCodec;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.web.RoutingContext;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Semaphore;


public class APIUsageCaptureHandler implements Handler<RoutingContext> {
    private static final Logger LOGGER = LoggerFactory.getLogger(APIUsageCaptureHandler.class);

    private final Vertx vertx;
    private HashMap<String, EndpointStat> pathMap;

    private static final int MAX_AVAILABLE = 1000;
    private final Semaphore queueSemaphore;

    private final long jsonProcessingInterval;

    private final Counter queueFullCounter;
    private final Counter logCycleSkipperCounter;
    private final Counter domainMissedCounter;
    private Instant lastJsonProcessTime;

    private JSONSerializer jsonSerializer;
    private Thread runningSerializer;

    public APIUsageCaptureHandler(long jsonIntervalMS, Vertx v, JSONSerializer jsonSerial) {
        vertx = v;
        pathMap = new HashMap<>();

        vertx.eventBus().consumer("APIUsage", this::handleMessage);

        jsonProcessingInterval = jsonIntervalMS;
        lastJsonProcessTime = Instant.now();
        this.jsonSerializer = jsonSerial;
        runningSerializer = new Thread();
        queueSemaphore = new Semaphore(MAX_AVAILABLE, true);
        queueFullCounter = Counter
                .builder("uid2.api_usage_queue_full")
                .description("counter for how many usage messages are dropped because the queue is full")
                .register(Metrics.globalRegistry);

        logCycleSkipperCounter = Counter
                .builder("uid2.api_usage_log_cycle_skipped")
                .description("counter for how many log cycles are skipped because the thread is still running")
                .register(Metrics.globalRegistry);

        domainMissedCounter = Counter
                .builder("uid2.api_usage_domain_missed")
                .description("counter for how many domains are missed because the dictionary is full")
                .register(Metrics.globalRegistry);
    }

    public void handleMessage(Message message) {
        ObjectMapper mapper = new ObjectMapper();
        MessageItem messageItem = null;
        try {
            messageItem = mapper.readValue(message.body().toString(), MessageItem.class);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        queueSemaphore.release();

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
                e.printStackTrace();
            }
        }
        String apiContact = messageItem.getApiContact();

        Integer siteId = messageItem.getSiteId();
        DomainStat domain = new DomainStat(referer, 1, apiContact);

        EndpointStat endpointStat = new EndpointStat(endpoint, siteId, apiVersion, domain);

        pathMap.merge(path, endpointStat, this::mergeEndpoint);
    }

    private EndpointStat mergeEndpoint(EndpointStat a, EndpointStat b) {
        a.Merge(b);
        return a;
    }


    @Override
    public void handle(RoutingContext routingContext) {
        routingContext.next();
        assert routingContext != null;

        String path = routingContext.request().path();
        String referer = routingContext.request().headers().get("Referer");
        ClientKey clientKey = (ClientKey) AuthMiddleware.getAuthClient(routingContext);
        MessageItem messageItem = new MessageItem(path, referer, clientKey.getContact(), clientKey.getSiteId());

        if(!queueSemaphore.tryAcquire()){
            queueFullCounter.increment();
            return;
        }

        ObjectMapper mapper = new ObjectMapper();
        try {
            vertx.eventBus().send("APIUsage", mapper.writeValueAsString(messageItem));
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        if(Duration.between(lastJsonProcessTime, Instant.now()).toMillis() >= jsonProcessingInterval){
            lastJsonProcessTime = Instant.now();
            if(runningSerializer.isAlive()){
               logCycleSkipperCounter.increment();
            } else {
                jsonSerializer.setArray(pathMap.values().toArray());
                runningSerializer = new Thread(jsonSerializer);
                runningSerializer.start();
                pathMap.clear();
            }

        }
    }

    static class MessageItem {
        private String path;
        private String referer;
        private String apiContact;
        private Integer siteId;

        //USED by json serial
        public MessageItem(){}

        public MessageItem(String p, String r, String api, Integer s){
            path = p;
            referer = r;
            apiContact = api;
            siteId = s;
        }

        public void setClientKey(ClientKey key) {
        }

        public void setReferer(String referer) {
            this.referer = referer;
        }

        public String getReferer() {
            return referer;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public String getPath() {
            return path;
        }

        public String getApiContact() {
            return apiContact;
        }

        public void setApiContact(String apiContact) {
            this.apiContact = apiContact;
        }

        public Integer getSiteId() {
            return siteId;
        }

        public void setSiteId(Integer siteId) {
            this.siteId = siteId;
        }
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


