package com.uid2.operator.util;

import io.vertx.core.http.impl.HttpUtils;

import java.util.Set;

public class HTTPPathMetricFilterOptimized {
    public static String filterPath(String actualPath, Set<String> pathSet) {
        try {
            String normalized = HttpUtils.normalizePath(actualPath);
            /* Optimization 1: Split that avoids array and regex initialization */
            int splitIndex = normalized.indexOf('?');
            if (splitIndex != -1) {
                normalized = normalized.substring(0, splitIndex);
            }

            if (normalized.charAt(normalized.length() - 1) == '/') {
                normalized = normalized.substring(0, normalized.length() - 1);
            }
            normalized = normalized.toLowerCase();

            if (pathSet == null || pathSet.isEmpty()) { return normalized; }

            /* Optimization 2: Remove for loop and regex matching */
            if (pathSet.contains(normalized)) { return normalized; }

            return "/unknown";
        } catch (IllegalArgumentException e) {
            return "/parsing_error";
        }
    }
}
