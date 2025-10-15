package com.uid2.operator.model;

import com.uid2.operator.vertx.ClientInputValidationException;

public enum IdentityVersion {
    V2(-1), // V2 raw UIDs don't encode version
    V3(0),
    V4(1);

    private final int value;

    IdentityVersion(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static IdentityVersion fromValue(int value) {
        return switch (value) {
            case -1 -> V2;
            case 0 -> V3;
            case 1 -> V4;
            default -> throw new ClientInputValidationException("Invalid valid for IdentityVersion: " + value);
        };
    }
}
