
package com.uid2.operator.util;

public class PrivacyBits {

    private static final int BIT_LEGACY = 0;
    private static final int BIT_CSTG = 1;
    private static final int BIT_CSTG_OPTOUT = 2;

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

    public void setClientSideTokenGenerate() { setBit(BIT_CSTG); }
    public boolean isClientSideTokenGenerated() {
        return isBitSet(BIT_CSTG);
    }

    public void setClientSideTokenGenerateOptout() { setBit(BIT_CSTG_OPTOUT); }
    public boolean isClientSideTokenOptedOut() {
        return isBitSet(BIT_CSTG_OPTOUT);
    }

    public void setLegacyBit() {
        setBit(BIT_LEGACY);//unknown why this bit is set in https://github.com/IABTechLab/uid2-operator/blob/dbab58346e367c9d4122ad541ff9632dc37bd410/src/main/java/com/uid2/operator/vertx/UIDOperatorVerticle.java#L534
    }

    private void setBit(int position) {
        bits |= (1 << position);
    }
    private boolean isBitSet(int position) {
        return (bits & (1 << position)) != 0;
    }
}
