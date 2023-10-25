package com.uid2.operator.operatorkey;

import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.google.common.base.Strings;
import com.uid2.operator.Const;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AzureVaultOperatorKeyRetriever implements IOperatorKeyRetriever {
    private static final Logger LOGGER = LoggerFactory.getLogger(AzureVaultOperatorKeyRetriever.class);
    private final JsonObject config;

    public AzureVaultOperatorKeyRetriever(JsonObject config) {
        this.config = config;
    }

    @Override
    public String retrieve() {
        // Check API token field first, if it's specified, use it.
        var tokenValue = this.config.getString(Const.Config.CoreApiTokenProp);

        if (!Strings.isNullOrEmpty(tokenValue)) {
            return tokenValue;
        }

        // Otherwise, try to load it from vault.
        var vaultName = this.config.getString(Const.Config.AzureVaultNameProp);
        if (Strings.isNullOrEmpty(vaultName)) {
            throw new IllegalArgumentException(Const.Config.AzureVaultNameProp + " is null or empty");
        }

        var secretName = this.config.getString(Const.Config.AzureSecretNameProp);
        if (Strings.isNullOrEmpty(secretName)) {
            throw new IllegalArgumentException(Const.Config.AzureSecretNameProp + " is null or empty");
        }

        return retrieveFromAzure(vaultName, secretName);
    }

    // ManagedIdentityCredential is used here.
    private String retrieveFromAzure(String vaultName, String secretName) {
        String vaultUrl = "https://" + vaultName + ".vault.azure.net";
        LOGGER.info(String.format("Load OperatorKey secret (%s) from %s", secretName, vaultUrl));
        // Use default ExponentialBackoff retry policy
        var secretClient = new SecretClientBuilder()
                .vaultUrl(vaultUrl)
                .credential(new ManagedIdentityCredentialBuilder().build())
                .buildClient();

        var retrievedSecret = secretClient.getSecret(secretName);

        LOGGER.info("OperatorKey secret is loaded.");
        return retrievedSecret.getValue();
    }
}
