package com.uid2.operator.model;

public enum IdentityMapPolicy {
    JustMap(0),
    RespectOptOut(1);

    public final int policy;

    IdentityMapPolicy(int policy) { this.policy = policy; }

    public static com.uid2.operator.model.IdentityMapPolicy fromValue(int value) {
        switch (value) {
            case 0: return JustMap;
            case 1: return RespectOptOut;
            default: throw new IllegalArgumentException();
        }
    }

    public static com.uid2.operator.model.IdentityMapPolicy defaultPolicy() {
        return JustMap;
    }

    public static IdentityMapPolicy respectOptOut() {
        return RespectOptOut;
    }
}
