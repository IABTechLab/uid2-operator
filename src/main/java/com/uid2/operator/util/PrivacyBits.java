
package com.uid2.operator.util;

public class PrivacyBits {

    // For historical reason this bit is set
    public static final PrivacyBits DEFAULT = PrivacyBits.fromInt(1);

    private static final int BIT_LEGACY = 0;
    private static final int BIT_CSTG = 1;
    private static final int BIT_CSTG_OPTOUT = 2;
    //DO NOT REUSE THIS BIT. DEPRECATED from UID2-2904 work
    private static final int BIT_CSTG_OPTOUT_RESPONSE_DEPRECATED = 3;

    private int bits = 0;

    public static PrivacyBits fromInt(int privacyBits) { return new PrivacyBits(privacyBits); }

    public PrivacyBits() {
    }

    public PrivacyBits(PrivacyBits pb) {
        bits = pb.bits;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !obj.getClass().equals(this.getClass())) {
            return false;
        }
        PrivacyBits other = (PrivacyBits)obj;
        return this.bits == other.bits;
    }

    @Override
    public int hashCode() {
        return this.bits;
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
    public boolean isLegacyBitSet() {
        return isBitSet(BIT_LEGACY);
    }

    private void setBit(int position) {
        bits |= (1 << position);
    }
    private boolean isBitSet(int position) {
        return (bits & (1 << position)) != 0;
    }
}
