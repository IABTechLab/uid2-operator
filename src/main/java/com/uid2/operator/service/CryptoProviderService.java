package com.uid2.operator.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

import javax.crypto.KeyAgreement;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class CryptoProviderService {
    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoProviderService.class);

    // ACCP provider name when available (after install()); null otherwise
    private static final String ACCP_PROVIDER_NAME = initAccpAsDefault();

    private static String initAccpAsDefault() {
        try {
            AmazonCorrettoCryptoProvider.install();
            if (AmazonCorrettoCryptoProvider.INSTANCE.getLoadingError() == null) {
                LOGGER.info("AmazonCorrettoCryptoProvider installed as default for all crypto");
                return AmazonCorrettoCryptoProvider.PROVIDER_NAME;
            }
        } catch (Throwable e) {
            LOGGER.info("AmazonCorrettoCryptoProvider is not available: {}", e.getMessage());
        }
        LOGGER.info("Using platform default crypto provider");
        return null;
    }

    /**
     * Create ECDH Key Agreement. Uses ACCP when installed as default; otherwise platform default (e.g. SunEC).
     * @return ECDH KeyAgreement
     * @throws NoSuchAlgorithmException
     */
    public static KeyAgreement createKeyAgreement() throws NoSuchAlgorithmException {
        if (ACCP_PROVIDER_NAME != null) {
            try {
                return KeyAgreement.getInstance("ECDH", ACCP_PROVIDER_NAME);
            } catch (NoSuchProviderException e) {
                LOGGER.info("{} is not available: {}", ACCP_PROVIDER_NAME, e.getMessage());
            }
        }
        return KeyAgreement.getInstance("ECDH");
    }
}
