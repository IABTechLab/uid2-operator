package com.uid2.operator.vertx;

public class ClientInputValidationException extends RuntimeException  {
    public ClientInputValidationException(String message) {
        super(message);
    }

    public ClientInputValidationException(String message, Exception e) {
        super(message, e);
    }
}
