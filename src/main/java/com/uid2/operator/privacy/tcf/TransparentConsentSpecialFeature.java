package com.uid2.operator.privacy.tcf;

public enum TransparentConsentSpecialFeature {
    PreciseGeolocationData          (1),
    ActiveScanDeviceCharacteristics (2);

    public final int value;
    private TransparentConsentSpecialFeature(int value) {
        this.value = value;
    }
}
