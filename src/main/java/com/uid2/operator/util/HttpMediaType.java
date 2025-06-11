package com.uid2.operator.util;

public enum HttpMediaType {
    TEXT_PLAIN("text/plain"),
    APPLICATION_JSON("application/json"),
    APPLICATION_OCTET_STREAM("application/octet-stream");

    private final String type;

    HttpMediaType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }
}