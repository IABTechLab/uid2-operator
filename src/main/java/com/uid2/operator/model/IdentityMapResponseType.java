package com.uid2.operator.model;

public enum IdentityMapResponseType {
    OPTOUT("optout"),
    INVALID_IDENTIFIER("invalid identifier");

    private final String value;

    IdentityMapResponseType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}

