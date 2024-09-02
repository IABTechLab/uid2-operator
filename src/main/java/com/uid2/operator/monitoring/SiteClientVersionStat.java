package com.uid2.operator.monitoring;

import java.util.Map;

public record SiteClientVersionStat(Integer siteId, Map<String, Integer> versionCounts) {
}
