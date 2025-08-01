package com.uid2.operator.model;

import com.uid2.operator.vertx.ClientInputValidationException;

public enum IdentityVersion {
    V3(0), V4(1);

    public final int value;

    IdentityVersion(int value) { this.value = value; }

    public static IdentityVersion fromValue(int value) {
        return switch (value) {
            case 0 -> V3;
            case 1 -> V4;
            default -> throw new ClientInputValidationException("Invalid valid for IdentityVersion: " + value);
        };
    }
}
