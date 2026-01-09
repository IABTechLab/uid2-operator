package com.uid2.operator.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.cryptools.AmazonCorrettoCryptoProvider;

import javax.crypto.KeyAgreement;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class CryptoProviderService {
    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoProviderService.class);

    // ECDH provider selection: tries ACCP first, falls back to default (SunEC)
    private static final String ECDH_PROVIDER_NAME = initEcdhProvider();
    private static final ThreadLocal<KeyAgreement> THREAD_LOCAL_KEY_AGREEMENT = ThreadLocal.withInitial(() -> {
        try {
            return createKeyAgreement();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Failed to create KeyAgreement", e);
        }
    });

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

    private static KeyAgreement createKeyAgreement() throws NoSuchAlgorithmException, NoSuchProviderException {
        if (ECDH_PROVIDER_NAME != null) {
            return KeyAgreement.getInstance("ECDH", ECDH_PROVIDER_NAME);
        }
        return KeyAgreement.getInstance("ECDH");
    }

    public static KeyAgreement getKeyAgreement() {
        return THREAD_LOCAL_KEY_AGREEMENT.get();
    }
}
