package com.uid2.operator.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.uid2.operator.vertx.ClientInputValidationException;

public enum IdentityEnvironment {
    TEST(0), INTEG(1), PROD(2);

    private final int value;

    IdentityEnvironment(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static IdentityEnvironment fromValue(int value) {
        return switch (value) {
            case 0 -> TEST;
            case 1 -> INTEG;
            case 2 -> PROD;
            default -> throw new ClientInputValidationException("Invalid valid for IdentityEnvironment: " + value);
        };
    }

    @JsonCreator
    public static IdentityEnvironment fromString(String value) {
        return switch (value.toLowerCase()) {
            case "test" -> TEST;
            case "integ" -> INTEG;
            case "prod" -> PROD;
            default -> throw new ClientInputValidationException("Invalid valid for IdentityEnvironment: " + value);
        };
    }
}
