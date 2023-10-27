package com.uid2.operator;

import com.google.api.gax.retrying.RetrySettings;
import com.google.cloud.secretmanager.v1.*;
import com.uid2.enclave.IOperatorKeyRetriever;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.threeten.bp.Duration;

import java.io.IOException;
import java.util.zip.CRC32C;
import java.util.zip.Checksum;

public class GcpOperatorKeyRetriever implements IOperatorKeyRetriever {
    private static final Logger LOGGER = LoggerFactory.getLogger(GcpOperatorKeyRetriever.class);

    private final SecretVersionName secretVersionName;
    /**
     * Retrieve secret value from GCP SecretManager
     * @param secretVersionName in "projects/{project}/secrets/{secret}/versions/{secret_version}" format
     */
    public GcpOperatorKeyRetriever(String secretVersionName){
        // Will throw IllegalArgument Exception for invalid format
        this.secretVersionName = SecretVersionName.parse(secretVersionName);
    }

    @Override
    public String retrieve() {
        var retrySetting = RetrySettings.newBuilder()
                .setInitialRetryDelay(Duration.ofSeconds(3))
                .setMaxAttempts(3)
                .build();
        var settingsBuilder =SecretManagerServiceSettings.newBuilder();
        settingsBuilder.accessSecretVersionSettings().setRetrySettings(retrySetting);

        try(var client = SecretManagerServiceClient.create(settingsBuilder.build())) {
            var response = client.accessSecretVersion(this.secretVersionName);
            String payload = response.getPayload().getData().toStringUtf8();
            LOGGER.info("Plaintext: %s\n", payload);
            
            return payload;
        } catch (IOException e) {
            LOGGER.error("Error: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }
}
