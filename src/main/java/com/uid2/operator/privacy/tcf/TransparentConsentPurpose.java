package com.uid2.operator.privacy.tcf;

/**
 * Purposes Definitions
 * https://iabeurope.eu/iab-europe-transparency-consent-framework-policies/
 */
public enum TransparentConsentPurpose {
    STORE_INFO_ON_DEVICE                    (1),
    SELECT_BASIC_ADS                        (2),
    CREATE_PERSONALIZED_ADS_PROFILE         (3),
    SELECT_PERSONALIZED_ADS                 (4),
    CREATE_PERSONALIZED_CONTENT_PROFILE     (5),
    SELECT_PERSONALIZED_CONTENT             (6),
    MEASURE_AD_PERFORMANCE                  (7),
    MEASURE_CONTENT_PERFORMANCE             (8),
    APPLY_MARKET_RESEARCH_GENERATE_INSIGHT  (9),
    DEVELOP_AND_IMPROVE_PRODUCTS            (10);

    public final int value;
    private TransparentConsentPurpose(int value) {
        this.value = value;
    }
}
