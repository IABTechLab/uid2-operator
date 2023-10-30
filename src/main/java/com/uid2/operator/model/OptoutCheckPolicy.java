package com.uid2.operator.model;

import com.uid2.operator.vertx.ClientInputValidationException;

public enum OptoutCheckPolicy {
    DoNotRespect(0),
    RespectOptOut(1);

    public final int policy;
    OptoutCheckPolicy(int policy) { this.policy = policy; }

    public static OptoutCheckPolicy fromValue(int value) {
        switch (value) {
            case 0: return DoNotRespect;
            case 1: return RespectOptOut;
            default: throw new ClientInputValidationException("Invalid value for OptoutCheckPolicy: " + value);
        }
    }

    public static OptoutCheckPolicy defaultPolicy() {
        return DoNotRespect;
    }

    public static OptoutCheckPolicy respectOptOut() {
        return RespectOptOut;
    }
}
