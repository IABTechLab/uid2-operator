package com.uid2.operator.model;

public enum IdentityScope {
    UID2(0),
    EUID(1);

    public final int value;

    IdentityScope(int value) { this.value = value; }

    public static IdentityScope fromValue(int value) {
        switch (value) {
            case 0: return UID2;
            case 1: return EUID;
            default: throw new IllegalArgumentException();
        }
    }

    public static IdentityScope fromString(String str) {
        switch (str.toLowerCase()) {
            case "uid2": return UID2;
            case "euid": return EUID;
            default: throw new IllegalArgumentException();
        }
    }
}
