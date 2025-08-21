package com.uid2.operator.model;

import com.uid2.operator.vertx.ClientInputValidationException;

public enum IdentityEnvironment {
    Test(0), Integ(1), Prod(2);

    public final int value;

    IdentityEnvironment(int value) {
        this.value = value;
    }

    public static IdentityEnvironment fromValue(int value) {
        return switch (value) {
            case 0 -> Test;
            case 1 -> Integ;
            case 2 -> Prod;
            default -> throw new ClientInputValidationException("Invalid valid for IdentityEnvironment: " + value);
        };
    }

    public static IdentityEnvironment fromString(String value) {
        return switch (value.toLowerCase()) {
            case "test" -> Test;
            case "integ" -> Integ;
            case "prod" -> Prod;
            default -> throw new ClientInputValidationException("Invalid valid for IdentityEnvironment: " + value);
        };
    }
}
