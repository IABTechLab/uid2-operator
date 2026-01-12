package com.uid2.operator.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

import javax.crypto.KeyAgreement;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class CryptoProviderService {
    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoProviderService.class);

    // ECDH provider selection: tries ACCP first, falls back to default (SunEC)
    private static final String ECDH_PROVIDER_NAME = initEcdhProvider();

    private static String initEcdhProvider() {
        // Try ACCP (Amazon Corretto Crypto Provider) first
        try {
            // Add ACCP at lowest priority so it doesn't become default for other algorithms            
            Security.addProvider(AmazonCorrettoCryptoProvider.INSTANCE);
            
            // Verify it works for ECDH
            KeyAgreement ka = KeyAgreement.getInstance("ECDH", AmazonCorrettoCryptoProvider.PROVIDER_NAME);
            LOGGER.info("ECDH using AmazonCorrettoCryptoProvider (added at lowest priority)");
            return AmazonCorrettoCryptoProvider.PROVIDER_NAME;
        } catch (Throwable e) {
            // ACCP not available
            LOGGER.info("AmazonCorrettoCryptoProvider is not available: {}", e.getMessage());
        }

        // Fall back to default provider
        LOGGER.info("ECDH using default provider (SunEC)");
        return null;
    }

    public static KeyAgreement createKeyAgreement() throws  NoSuchAlgorithmException {
        if (ECDH_PROVIDER_NAME != null) {
            try {
                return KeyAgreement.getInstance("ECDH", ECDH_PROVIDER_NAME);
            } catch (NoSuchProviderException e) {
                LOGGER.info("{} is not available: {}", ECDH_PROVIDER_NAME, e.getMessage());
            }
        }
        return KeyAgreement.getInstance("ECDH");
    }
}
