package com.uid2.operator.privacy.tcf;

public class TransparentConsentParseResult {
    private final boolean success;
    private final String failureReason;
    private final TransparentConsent tcString;

    public TransparentConsentParseResult(TransparentConsent parsedConsent) {
        this.tcString = parsedConsent;
        this.success = true;
        this.failureReason = "";
    }

    public TransparentConsentParseResult(String failureReason) {
        this.tcString = null;
        this.success = false;
        this.failureReason = failureReason;
    }

    public boolean isSuccess() { return success; }
    public TransparentConsent getTCString() { return tcString; }
    public String getFailureReason() { return failureReason; }
}
