package com.uid2.operator.privacy.tcf;

import java.util.stream.IntStream;
import java.util.stream.Stream;

import com.iabtcf.decoder.TCString;
import com.uid2.operator.vertx.ClientInputValidationException;

/**
 * Wrapper around com.iabtcf.decoder.TCString
 */
public class TransparentConsent {

    private final TCString tcString;

    public TransparentConsent(String consentString) throws ClientInputValidationException {
        try {
            this.tcString = TCString.decode(consentString);
        } catch(Exception e) {
            throw new ClientInputValidationException("unable to parse consentString", e);
        }
    }

    public boolean hasConsent(int vendorId, TransparentConsentPurpose ... purposes) {
        // DevNote: Here we enumerates a bitfield and reconstruct it.
        //          Using raw bitfield inside TCString would be more efficient.
        //          However, we do not have access to it

        final int requiredBits = Stream.of(purposes)
            .mapToInt(x -> x.value)
            .reduce(0, (f, x) -> f | 1 << x);
        return (IntStream.concat(
                this.tcString.getVendorConsent().contains(vendorId) ? 
                    this.tcString.getPurposesConsent().toStream() :
                    IntStream.of(),
                this.tcString.getVendorLegitimateInterest().contains(vendorId) ?
                    this.tcString.getPurposesLITransparency().toStream() :
                    IntStream.of())
                .reduce(0, (f, x) -> (f | (1 << x))) 
                & requiredBits) == requiredBits;
    }

    public boolean hasSpecialFeature(TransparentConsentSpecialFeature feature) {
        return this.tcString.getSpecialFeatureOptIns().contains(feature.value);
    }
}
