package com.uid2.operator.monitoring;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

public class ClientVersionStatRecorder {
    private final int siteClientBucketLimit;
    private final Map<Integer, Map<String, Integer>> clientVersionToSiteCount = new HashMap<>();

    public ClientVersionStatRecorder(int maxVersionBucketsPerSite) {
        this.siteClientBucketLimit = maxVersionBucketsPerSite;
    }

    public Stream<SiteClientVersionStat> getStatsView() {
        return clientVersionToSiteCount.entrySet().stream().map(entry -> new SiteClientVersionStat(entry.getKey(), entry.getValue()));
    }

    public void clear() {
        clientVersionToSiteCount.clear();
    }

    public void add(Integer siteId, String clientVersion) {
        if (siteId == null || clientVersion == null) {
            return;
        }

        var clientVersionCounts = clientVersionToSiteCount.computeIfAbsent(siteId, k -> new HashMap<>());

        var count = clientVersionCounts.get(clientVersion);
        if (count == null && clientVersionCounts.size() >= siteClientBucketLimit) {
            var notRecordedCount = clientVersionCounts.getOrDefault("NotRecorded", 0);
            clientVersionCounts.put("NotRecorded", notRecordedCount + 1);
        }
        else if (count == null) {
            clientVersionCounts.put(clientVersion, 1);
        }
        else {
            clientVersionCounts.put(clientVersion, count + 1);
        }
    }
}
