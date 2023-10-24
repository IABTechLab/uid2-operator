package com.uid2.operator.operatorkey;

import io.vertx.core.json.JsonObject;

public class OperatorKeyRetrieverFactory {
    public static IOperatorKeyRetriever getOperatorKeyRetriever(JsonObject config) {
        String enclavePlatform = config.getString("enclave_platform", "");
        switch (enclavePlatform) {
            case "azure-cc":
                return new AzureVaultOperatorKeyRetriever(config);
            default:
                return new ConfigOperatorKeyRetriever(config);
        }
    }
}
