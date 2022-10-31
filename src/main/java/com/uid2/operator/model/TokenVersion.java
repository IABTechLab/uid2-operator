package com.uid2.operator.model;

public enum TokenVersion {
    V2(2),
    V3(112);

    public final int rawVersion;

    TokenVersion(int rawVersion) { this.rawVersion = rawVersion; }
}
