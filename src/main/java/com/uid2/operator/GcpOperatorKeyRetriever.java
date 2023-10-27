package com.uid2.operator;

import com.google.api.gax.retrying.RetrySettings;
import com.google.cloud.secretmanager.v1.*;
import com.uid2.enclave.IOperatorKeyRetriever;
import org.threeten.bp.Duration;

import java.io.IOException;
import java.util.zip.CRC32C;
import java.util.zip.Checksum;

public class GcpOperatorKeyRetriever implements IOperatorKeyRetriever {
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
            System.out.printf("Plaintext: %s\n", payload);
            return payload;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
