package com.uid2.operator.vertx;

public class ClientInputException extends RuntimeException  {
    public ClientInputException(String message) {
        super(message);
    }

    public ClientInputException(String message, Exception e) {
        super(message, e);
    }
}
