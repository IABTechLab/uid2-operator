package com.uid2.operator.util;

public class PrivacyBits {
    private int bits = 0;

    public static PrivacyBits fromInt(int privacyBits) { return new PrivacyBits(privacyBits); }

    public PrivacyBits() {
    }

    public PrivacyBits(int bits) {
        this.bits = bits;
    }

    public int getAsInt() {
        return bits;
    }

    public void setClientSideTokenGenerate() { setBit(1); }
    public boolean isClientSideTokenGenerateBitSet() {
        return (bits & (1 << 1)) != 0;
    }

    public void setLegacyBit() {
        setBit(0);//unknown why this bit is set in https://github.com/IABTechLab/uid2-operator/blob/dbab58346e367c9d4122ad541ff9632dc37bd410/src/main/java/com/uid2/operator/vertx/UIDOperatorVerticle.java#L534
    }

    private void setBit(int position) {
        bits |= (1 << position);
    }
    private boolean isBitSet(int position) {
        return (bits & (1 << position)) != 0;
    }
}
