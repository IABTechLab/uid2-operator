package com.uid2.operator.model;

public enum OperatorType {
    Service(1),
    Snowflake(17),
    Unknown(-1);

    public final int value;

    OperatorType(int value) {
        this.value = value;
    }

    public static OperatorType fromValue(int value) {
        switch (value) {
            case 1:
                return Service;
            case 17:
                return Snowflake;
            default:
                return Unknown;
        }
    }
}
