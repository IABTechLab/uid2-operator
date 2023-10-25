package com.uid2.operator.operatorkey;

import com.uid2.operator.Const;
import io.vertx.core.json.JsonObject;
import org.junit.Assert;
import org.junit.jupiter.api.Test;

import static org.junit.Assert.assertEquals;

class AzureVaultOperatorKeyRetrieverTest {
    @Test
    public void testReturnApiTokenIfSpecified() {
        var OPERATOR_KEY = "operator_key";
        var config = new JsonObject().put(Const.Config.CoreApiTokenProp, OPERATOR_KEY);

        var sut = new AzureVaultOperatorKeyRetriever(config);
        var key = sut.retrieve();

        assertEquals(OPERATOR_KEY, key);
    }

    @Test
    public void testArgumentCheck_NoVaultName() {
        var config = new JsonObject();

        var sut = new AzureVaultOperatorKeyRetriever(config);
        Assert.assertThrows(IllegalArgumentException.class, () -> sut.retrieve());
    }

    @Test
    public void testArgumentCheck_NoSecretName() {
        var config = new JsonObject().put(Const.Config.AzureVaultNameProp, "dummy");

        var sut = new AzureVaultOperatorKeyRetriever(config);
        Assert.assertThrows(IllegalArgumentException.class, () -> sut.retrieve());
    }
}
