package com.uid2.operator.model;

public enum IdentityType {
    Email(0), Phone(1);

    public final int value;

    IdentityType(int value) { this.value = value; }

    public static IdentityType fromValue(int value) {
        switch (value) {
            case 0: return Email;
            case 1: return Phone;
            default: throw new IllegalArgumentException();
        }
    }
}
