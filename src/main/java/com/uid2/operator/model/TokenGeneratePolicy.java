package com.uid2.operator.model;

public enum TokenGeneratePolicy {
    JustGenerate(0),
    RespectOptOut(1);

    public final int policy;

    TokenGeneratePolicy(int policy) { this.policy = policy; }

    public static TokenGeneratePolicy fromValue(int value) {
        switch (value) {
            case 0: return JustGenerate;
            case 1: return RespectOptOut;
            default: throw new IllegalArgumentException();
        }
    }

    public static TokenGeneratePolicy defaultPolicy() {
        return JustGenerate;
    }
}
