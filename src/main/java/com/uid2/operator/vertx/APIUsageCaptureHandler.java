package com.uid2.operator.vertx;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.middleware.AuthMiddleware;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.Message;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.web.RoutingContext;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Semaphore;


public class APIUsageCaptureHandler implements Handler<RoutingContext> {
    private static final Logger LOGGER = LoggerFactory.getLogger(APIUsageCaptureHandler.class);

    private final Vertx vertx;
    private HashMap<String, EndpointStat> pathMap;

    private static final int MAX_AVAILABLE = 1000;
    private final Semaphore jsonSemaphore;
    private final Semaphore queueSemaphore;

    public APIUsageCaptureHandler(long periodicDurationMS, Vertx v) {
        vertx = v;
        pathMap = new HashMap<>();

        vertx.eventBus().consumer("APIUsage", this::handleQueue);

        vertx.setPeriodic(periodicDurationMS, this::handleJsonSerial);
        jsonSemaphore = new Semaphore(MAX_AVAILABLE, true);
        queueSemaphore = new Semaphore(MAX_AVAILABLE, true);
    }

    public void handleJsonSerial(Long l) {
        try {
            jsonSemaphore.acquire(MAX_AVAILABLE);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        Object[] localValues = pathMap.values().toArray();
        pathMap.clear();
        jsonSemaphore.release(MAX_AVAILABLE);


        ObjectMapper mapper = new ObjectMapper();
        String jsonString = null;
        for (int i = 0; i < localValues.length; i++) {
            try {
                jsonString = mapper.writeValueAsString(localValues[i]);
            } catch (JsonProcessingException e) {
                e.printStackTrace();
            }
            LOGGER.debug(jsonString);
        }
    }

    public void handleQueue(Message message) {
        EndpointStat endpointStat = (EndpointStat) message.body();
        try {
            jsonSemaphore.acquire();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        pathMap.merge(endpointStat.path, endpointStat, this::mergeEndpoint);
        jsonSemaphore.release();
    }

    private EndpointStat mergeEndpoint(EndpointStat a, EndpointStat b) {
        a.Merge(b);
        return a;
    }


    @Override
    public void handle(RoutingContext routingContext) {
        routingContext.next();
        queueSemaphore.release();
        assert routingContext != null;
        String path = routingContext.request().path();
        String apiVersion = "v0";
        String endpoint = path.substring(1);

        if(path.charAt(1) == 'v') {
            int apiVIndex = path.indexOf("/", 1);
            apiVersion = path.substring(1, apiVIndex);
            endpoint = path.substring(apiVIndex+1);
        }

        String referer = routingContext.request().headers().get("Referer");
        if(referer == null){
            referer = "unknown";
        } else {
            //TODO parse out domain name
            referer = referer;
        }
        ClientKey clientKey = (ClientKey) AuthMiddleware.getAuthClient(routingContext);
        String apiContact = clientKey.getContact();

        Integer siteId = clientKey.getSiteId();
        DomainStat domain = new DomainStat(referer, 1, apiContact);

        EndpointStat endpointClass = new EndpointStat(endpoint, path, siteId, apiVersion, domain);

        if(!queueSemaphore.tryAcquire()){
            //Queue is full
            System.out.println("Queue is full");
            return;
        }
        vertx.eventBus().send("APIUsage", endpointClass);
    }


    static class DomainStat {
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
        private String path;
        private Integer siteId;
        private String apiVersion;
        private LinkedList<DomainStat> domainList;

        private HashMap<String, Integer> domainMap;

        public EndpointStat(String e, String p, Integer s, String a, DomainStat d) {
            endpoint = e;
            siteId = s;
            apiVersion = a;
            domainList = new LinkedList<>();
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

        public LinkedList<DomainStat> getDomainList() {
            return domainList;
        }

        public void Merge(EndpointStat other) {
            other.domainList.forEach(this::AddDomain);
        }

        public void AddDomain(DomainStat d) {
            String domainName = d.getDomain();
            if(domainMap.containsKey(domainName)) {
                domainList.get(domainMap.get(domainName)).merge(d);
            } else {
                domainList.add(d);
                domainMap.put(domainName, domainList.size()-1);
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


