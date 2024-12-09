package com.uid2.operator.model.identities;

import com.uid2.operator.vertx.ClientInputValidationException;

public enum DiiType {
    Email(0), Phone(1);

    public final int value;

    DiiType(int value) { this.value = value; }

    public static DiiType fromValue(int value) {
        switch (value) {
            case 0: return Email;
            case 1: return Phone;
            default: throw new ClientInputValidationException("Invalid valid for IdentityType: " + value);
        }
    }
}
