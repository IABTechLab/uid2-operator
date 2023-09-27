package com.uid2.operator;

import com.uid2.shared.model.TokenVersion;
import org.junit.jupiter.api.Test;

import com.uid2.operator.model.IdentityScope;
import com.uid2.shared.auth.Role;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.junit5.VertxTestContext;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

public class EUIDOperatorVerticleTest extends UIDOperatorVerticleTest {
    public EUIDOperatorVerticleTest() throws IOException {
    }

    @Override
    protected TokenVersion getTokenVersion() {return TokenVersion.V3;}

    @Override
    protected IdentityScope getIdentityScope() { return IdentityScope.EUID; }
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
        sendTokenGenerate("v2", vertx, "", v2Payload, 400, json -> testContext.completeNow());
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
        sendTokenGenerate("v2", vertx, "", v2Payload, 200, json -> testContext.completeNow());

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
        sendTokenGenerate("v2", vertx, "", v2Payload, 200, json -> {
            assertFalse(json.containsKey("body"));
            assertEquals("insufficient_user_consent", json.getString("status"));
            testContext.completeNow();
        });
    }
}

