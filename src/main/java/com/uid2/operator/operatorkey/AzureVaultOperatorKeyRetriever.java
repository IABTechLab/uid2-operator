package com.uid2.operator.operatorkey;

import com.azure.identity.DefaultAzureCredentialBuilder;
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
        
        return retrieveInternal(vaultName, secretName);
    }

    // DefaultAzureCredential code can automatically discover and use a managed identity that is assigned to
    // an App Service, Virtual Machine, or other services.
    private String retrieveInternal(String vaultName, String secretName) {
        String vaultUrl = "https://" + vaultName + ".vault.azure.net";
        LOGGER.info(String.format("Load secret (%s) from %s", vaultUrl, secretName));
        // It has default ExponentialBackoff retry policy
        var secretClient = new SecretClientBuilder()
                .vaultUrl(vaultUrl)
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();

        var retrievedSecret = secretClient.getSecret(secretName);

        // TODO: delete it later.
        LOGGER.info("Secret is loaded. Value: " + retrievedSecret.getValue());
        return retrievedSecret.getValue();
    }
}
