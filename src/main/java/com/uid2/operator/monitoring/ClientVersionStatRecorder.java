package com.uid2.operator.monitoring;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

public class ClientVersionStatRecorder {
    private static final String NOT_RECORDED = "<Not recorded>";
    private final int siteClientBucketLimit;
    private final Map<Integer, Map<String, Integer>> siteIdToVersionCounts = new HashMap<>();

    public ClientVersionStatRecorder(int maxVersionBucketsPerSite) {
        this.siteClientBucketLimit = maxVersionBucketsPerSite;
    }

    public Stream<ILoggedStat> getStatsView() {
        return siteIdToVersionCounts.entrySet().stream().map(entry -> new SiteClientVersionStat(entry.getKey(), entry.getValue()));
    }

    private void removeLowVersionCounts(int siteId) {
        var versionCounts = siteIdToVersionCounts.get(siteId);
        if (versionCounts == null) {
            return;
        }

        // Remove 3 items to avoid a couple of new version values from continuously evicting each other
        var lowestEntries = versionCounts.entrySet().stream()
                .sorted(Map.Entry.comparingByValue())
                .filter(entry -> !entry.getKey().equals(NOT_RECORDED))
                .limit(3)
                .toList();
        for (var entry : lowestEntries) {
            var notRecordedCount = versionCounts.getOrDefault(NOT_RECORDED, 0);
            versionCounts.put(NOT_RECORDED, notRecordedCount + entry.getValue());
            versionCounts.remove(entry.getKey());
        }
    }

    public void add(Integer siteId, String clientVersion) {
        if (siteId == null || clientVersion == null || clientVersion.isBlank()) {
            return;
        }

        var clientVersionCounts = siteIdToVersionCounts.computeIfAbsent(siteId, k -> new HashMap<>());

        var count = clientVersionCounts.getOrDefault(clientVersion, 0);
        if (count == 0 && clientVersionCounts.size() >= siteClientBucketLimit) {
            removeLowVersionCounts(siteId);
        }
        clientVersionCounts.put(clientVersion, count + 1);
    }
}
