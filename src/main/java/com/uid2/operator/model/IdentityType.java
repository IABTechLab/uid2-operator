package com.uid2.operator.model;

import com.uid2.operator.vertx.ClientInputValidationException;

public enum IdentityType {
    Email(0),
    Phone(1);

    private final int value;

    IdentityType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static IdentityType fromValue(int value) {
        return switch (value) {
            case 0 -> Email;
            case 1 -> Phone;
            default -> throw new ClientInputValidationException("Invalid valid for IdentityType: " + value);
        };
    }
}
