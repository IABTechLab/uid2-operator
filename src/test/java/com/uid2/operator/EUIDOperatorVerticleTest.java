package com.uid2.operator;

import com.uid2.operator.model.IdentityScope;
import io.vertx.core.json.JsonObject;

public class EUIDOperatorVerticleTest extends UIDOperatorVerticleTest {
    @Override
    public void setupConfig(JsonObject config) {
        config.put("identity_scope", getIdentityScope().toString());
        config.put("advertising_token_v3", true);
        config.put("refresh_token_v3", true);
        config.put("identity_v3", useIdentityV3());
    }

    @Override
    protected boolean useIdentityV3() { return true; }
    @Override
    protected IdentityScope getIdentityScope() { return IdentityScope.EUID; }
}
