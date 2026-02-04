package com.uid2.operator;

import org.junit.jupiter.api.Test;

import com.iabtcf.encoder.TCStringEncoder;
import com.iabtcf.utils.BitSetIntIterable;
import com.uid2.operator.model.IdentityScope;
import com.uid2.shared.auth.Role;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.junit5.VertxTestContext;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class EUIDOperatorVerticleTest extends UIDOperatorVerticleTest {
    @Override
    protected IdentityScope getIdentityScope() {
        return IdentityScope.EUID;
    }

    @Override
    protected boolean useRawUidV3() {
        return true;
    }

    @Override
    protected void addAdditionalTokenGenerateParams(JsonObject payload) {
        if (payload != null && !payload.containsKey("tcf_consent_string")) {
            payload.put("tcf_consent_string", "CPehNtWPehNtWABAMBFRACBoALAAAEJAAIYgAKwAQAKgArABAAqAAA");
        }
    }

    @Test
    void badRequestOnInvalidTcfConsent(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        final String emailAddress = "test@uid2.com";
        final JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);
        v2Payload.put("tcf_consent_string", "invalid_consent_string");
        sendTokenGenerate(vertx, v2Payload, 400, json -> testContext.completeNow());
    }

    @Test
    void noTCFString(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        final String emailAddress = "test@uid2.com";
        final JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);
        sendTokenGenerate(vertx, v2Payload, 200, json -> testContext.completeNow(), false);

    }

    @Test
    void noContentOnInsufficientTcfConsent(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        final String emailAddress = "test@uid2.com";
        final JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);
        // this TCString is missing consent for purpose #1
        v2Payload.put("tcf_consent_string", "CPehXK9PehXK9ABAMBFRACBoADAAAEJAAIYgAKwAQAKgArABAAqAAA");
        sendTokenGenerate(vertx, v2Payload, 200, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("insufficient_user_consent", json.getString("status"));
            testContext.completeNow();
        });
    }

    @Test
    void consentPassesWhenPreciseGeolocationSpecialFeatureIsMissing(Vertx vertx, VertxTestContext testContext) {
        final int clientSiteId = 201;
        fakeAuth(clientSiteId, Role.GENERATOR);
        setupSalts();
        setupKeys();

        final String emailAddress = "test@uid2.com";
        final JsonObject v2Payload = new JsonObject();
        v2Payload.put("email", emailAddress);
        // TCF string with all required purposes but WITHOUT PreciseGeolocation special feature (feature 1)
        String tcfStringWithoutPreciseGeolocation = createTcfConsentString(
                new int[] { 21 },           // vendor consent
                new int[] { 21 },           // vendor LI
                new int[] { 1, 3, 4 },      // purpose consents (1, 3, 4)
                new int[] { 2, 7, 10 },     // purpose LI (2, 7, 10)
                new int[] {}                // NO special features - PreciseGeolocation (1) is missing
        );
        v2Payload.put("tcf_consent_string", tcfStringWithoutPreciseGeolocation);
        sendTokenGenerate(vertx, v2Payload, 200, json -> {
            assertTrue(json.containsKey("body"));
            assertEquals("success", json.getString("status"));
            testContext.completeNow();
        });
    }

    private String createTcfConsentString(int[] vendorConsent, int[] vendorLI, int[] purposesConsent, int[] purposesLI, int[] specialFeatureOptIns) {
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
                .addSpecialFeatureOptIns(BitSetIntIterable.from(specialFeatureOptIns))
                .publisherCC("DE")
                .addVendorConsent(BitSetIntIterable.from(vendorConsent))
                .addVendorLegitimateInterest(BitSetIntIterable.from(vendorLI))
                .purposeOneTreatment(true)
                .addPurposesConsent(BitSetIntIterable.from(purposesConsent))
                .addPurposesLITransparency(BitSetIntIterable.from(purposesLI))
                .encode();
    }
}

