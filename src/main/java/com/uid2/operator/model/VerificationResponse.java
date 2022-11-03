package com.uid2.operator.model;

public class VerificationResponse {
    private final String verificationToken;
    private final int verificationCode;

    public VerificationResponse(String verificationToken, int verificationCode) {
        this.verificationToken = verificationToken;
        this.verificationCode = verificationCode;
    }
}
