package com.uid2.operator.monitoring;

import java.util.Map;
import java.util.Objects;

public final class SiteClientVersionStat implements ILoggedStat {
    private final Integer siteId;
    private final Map<String, Integer> versionCounts;

    public SiteClientVersionStat(Integer siteId, Map<String, Integer> versionCounts) {
        this.siteId = siteId;
        this.versionCounts = versionCounts;
    }

    @Override
    public String GetLogPrefix() {
        return "version log; siteId=%d versions=".formatted(siteId);
    }

    @Override
    public Object GetValueToLog() {
        return versionCounts;
    }
}
