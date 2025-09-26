package com.uid2.operator.model;

import com.uid2.operator.vertx.ClientInputValidationException;

public enum IdentityScope {
    UID2(0),
    EUID(1);

    private final int value;

    IdentityScope(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static IdentityScope fromValue(int value) {
        return switch (value) {
            case 0 -> UID2;
            case 1 -> EUID;
            default -> throw new ClientInputValidationException("Invalid value for IdentityScope: " + value);
        };
    }

    public static IdentityScope fromString(String str) {
        return switch (str.toLowerCase()) {
            case "uid2" -> UID2;
            case "euid" -> EUID;
            default -> throw new ClientInputValidationException("Invalid string for IdentityScope: " + str);
        };
    }
}
