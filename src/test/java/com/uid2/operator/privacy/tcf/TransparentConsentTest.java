package com.uid2.operator.privacy.tcf;

import com.iabtcf.encoder.TCStringEncoder;
import com.iabtcf.utils.BitSetIntIterable;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TransparentConsentTest {
    @Test
    void smokeTest() {
        final TransparentConsent tcs = new TransparentConsent(createConsentStringV2(
                new int[] { 21 },
                new int[] { 21 },
                new int[] { 1, 3, 4 },
                new int[] { 2, 7, 10 },
                new int[] { 1 }));

        assertTrue(tcs.hasConsent(21,
                TransparentConsentPurpose.STORE_INFO_ON_DEVICE,
                TransparentConsentPurpose.CREATE_PERSONALIZED_ADS_PROFILE,
                TransparentConsentPurpose.SELECT_PERSONALIZED_ADS,
                TransparentConsentPurpose.SELECT_BASIC_ADS,
                TransparentConsentPurpose.MEASURE_AD_PERFORMANCE,
                TransparentConsentPurpose.DEVELOP_AND_IMPROVE_PRODUCTS
        ));
    }

    @Test
    void testInsufficientPurposeConsent() {
        final TransparentConsent tcs = new TransparentConsent(createConsentStringV2(
                new int[] { 21 },
                new int[] { 21 },
                new int[] { 1, 3 },         // missing 4 TransparentConsentPurpose.SELECT_PERSONALIZED_ADS
                new int[] { 2, 7, 10 },
                new int[] { 1 }));

        assertFalse(tcs.hasConsent(21,
                TransparentConsentPurpose.STORE_INFO_ON_DEVICE,
                TransparentConsentPurpose.CREATE_PERSONALIZED_ADS_PROFILE,
                TransparentConsentPurpose.SELECT_PERSONALIZED_ADS,
                TransparentConsentPurpose.SELECT_BASIC_ADS,
                TransparentConsentPurpose.MEASURE_AD_PERFORMANCE,
                TransparentConsentPurpose.DEVELOP_AND_IMPROVE_PRODUCTS
        ));
    }

    @Test
    void testInsufficientPurposeLI() {
        final TransparentConsent tcs = new TransparentConsent(createConsentStringV2(
                new int[] { 21 },
                new int[] { 21 },
                new int[] { 1, 3, 4 },
                new int[] { 2, 10 },    // missing 7 TransparentConsentPurpose.MEASURE_AD_PERFORMANCE
                new int[] { 1 }));

        assertFalse(tcs.hasConsent(21,
                TransparentConsentPurpose.STORE_INFO_ON_DEVICE,
                TransparentConsentPurpose.CREATE_PERSONALIZED_ADS_PROFILE,
                TransparentConsentPurpose.SELECT_PERSONALIZED_ADS,
                TransparentConsentPurpose.SELECT_BASIC_ADS,
                TransparentConsentPurpose.MEASURE_AD_PERFORMANCE,
                TransparentConsentPurpose.DEVELOP_AND_IMPROVE_PRODUCTS
        ));
    }

    @Test
    void testVendorConsentNotPresent() {
        final TransparentConsent tcs = new TransparentConsent(createConsentStringV2(
                new int[] { 17 },          // vendor 21 is not present
                new int[] { 21 },
                new int[] { 1, 3, 4 },
                new int[] { 2, 7, 10 },    // missing 7 TransparentConsentPurpose.MEASURE_AD_PERFORMANCE
                new int[] { 1 }));

        assertFalse(tcs.hasConsent(21,
                TransparentConsentPurpose.STORE_INFO_ON_DEVICE,
                TransparentConsentPurpose.CREATE_PERSONALIZED_ADS_PROFILE,
                TransparentConsentPurpose.SELECT_PERSONALIZED_ADS,
                TransparentConsentPurpose.SELECT_BASIC_ADS,
                TransparentConsentPurpose.MEASURE_AD_PERFORMANCE,
                TransparentConsentPurpose.DEVELOP_AND_IMPROVE_PRODUCTS
        ));
    }

    @Test
    void testVendorLINotPresent() {
        final TransparentConsent tcs = new TransparentConsent(createConsentStringV2(
                new int[] { 21 },
                new int[] { 17 },          // vendor 21 is not present
                new int[] { 1, 3, 4 },
                new int[] { 2, 7, 10 },
                new int[] { 1 }));

        assertFalse(tcs.hasConsent(21,
                TransparentConsentPurpose.STORE_INFO_ON_DEVICE,
                TransparentConsentPurpose.CREATE_PERSONALIZED_ADS_PROFILE,
                TransparentConsentPurpose.SELECT_PERSONALIZED_ADS,
                TransparentConsentPurpose.SELECT_BASIC_ADS,
                TransparentConsentPurpose.MEASURE_AD_PERFORMANCE,
                TransparentConsentPurpose.DEVELOP_AND_IMPROVE_PRODUCTS
        ));
    }

    private String createConsentStringV2(int[] vendorConsent, int[] vendorLI, int[] purposesConsent, int[] purposesLI, int[] featureOptIns) {
        return TCStringEncoder.newBuilder()
                .version(2)
                .created(Instant.now())
                .lastUpdated(Instant.now())
                .cmpId(1)
                .cmpVersion(12)
                .consentScreen(1)
                .consentLanguage("FR")
                .vendorListVersion(2)
                .tcfPolicyVersion(1)
                .isServiceSpecific(true)
                .useNonStandardStacks(false)
                .addSpecialFeatureOptIns(BitSetIntIterable.from(featureOptIns))
                .publisherCC("DE")
                .addVendorConsent(BitSetIntIterable.from(vendorConsent))
                .addVendorLegitimateInterest(BitSetIntIterable.from(vendorLI))
                .purposeOneTreatment(true)
                .addPurposesConsent(BitSetIntIterable.from(purposesConsent))
                .addPurposesLITransparency(BitSetIntIterable.from(purposesLI))
                .encode();
    }
}
