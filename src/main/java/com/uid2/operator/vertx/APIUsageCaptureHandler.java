package com.uid2.operator.vertx;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.middleware.AuthMiddleware;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.ext.web.RoutingContext;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

//TODO Maybe Come up with a better name
public class APIUsageCaptureHandler implements Handler<RoutingContext> {
    private final ConcurrentLinkedQueue<RoutingContext> requestQueue = new ConcurrentLinkedQueue<>();
    private final Vertx vertx;
    private ConcurrentHashMap<String, Endpoint> pathMap;

    public APIUsageCaptureHandler() {
        vertx = Vertx.vertx();
        pathMap = new ConcurrentHashMap<>();
        vertx.setPeriodic(1000, this::handleJsonSerial);
    }

    public void handleJsonSerial(Long l) {
        System.out.println(l);
        Object[] keys = pathMap.keySet().toArray();
        for (int i = 0; i < pathMap.size(); i++) {
            System.out.println(pathMap.get(keys[i]));
        }
    }

    public void handleQueue(Void v) {
        RoutingContext routingContext = requestQueue.poll();
        assert routingContext != null;
        //TODO Add case for no version api
        String path = routingContext.request().path();
        int apiVIndex = path.indexOf("/", 1);
        String apiVersion = path.substring(1, apiVIndex);
        String endpoint = path.substring(apiVIndex+1);

        String referer = routingContext.request().headers().get("Referer");
        ClientKey clientKey = (ClientKey) AuthMiddleware.getAuthClient(routingContext);
        String apiContact = clientKey.getContact();

        Integer siteId = clientKey.getSiteId();
        Domain domain = new Domain(referer, 1, apiContact);

        Endpoint endpointClass = new Endpoint(endpoint, siteId, apiVersion, domain);

        pathMap.merge(path, endpointClass, this::mergeEndpoint);
    }

    private Endpoint mergeEndpoint(Endpoint a, Endpoint b) {
        a.Merge(b);
        return a;
    }


    @Override
    public void handle(RoutingContext routingContext) {
        routingContext.next();
        requestQueue.offer(routingContext);
        vertx.runOnContext(this::handleQueue);
    }
}

class Domain {
    private String domain;
    private Integer count;
    private String apiContact;

    public Domain(String d, Integer c, String a) {
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

    public void merge(Domain d) {
        count += d.getCount();
    }

    public String toString() {
        return "{Domain: " + domain + ", Count: " + count + ", Api_Contact: "+ apiContact + "}";
    }
}

//TODO better name for this too
class Endpoint {
    private String endpoint;
    private Integer siteId;
    private String apiVersion;
    private LinkedList<Domain> domainList;

    private HashMap<String, Integer> domainMap;

    public Endpoint(String e, Integer s, String a, Domain d) {
        endpoint = e;
        siteId = s;
        apiVersion = a;
        domainList = new LinkedList<>();
        domainMap = new HashMap<>();

        AddDomain(d);
    }

    public void Merge(Endpoint other) {
        other.domainList.forEach(this::AddDomain);
    }

    public void AddDomain(Domain d) {
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
