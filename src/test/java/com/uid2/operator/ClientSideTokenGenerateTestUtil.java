package com.uid2.operator;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ClientSideTokenGenerateTestUtil {

    public static PublicKey stringToPublicKey(String publicKeyString, KeyFactory kf) {
        //pretending to be the publisher running the javascript generating public key given by UID2 team
        //which has prefixes like 'UID2-X-T-' and we need to remove it first
        final byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString.substring(9));
        final X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(publicKeyBytes);
        try {
            return kf.generatePublic(pkSpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey stringToPrivateKey(String privateKeyString, KeyFactory kf) {
        //note that this method is for pretending javascript generating a private key and therefore
        //there's no prefixes like the public key we gave to the publishers so no substring call is required here
        final byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
        final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        try {
            return kf.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static SecretKey deriveKey(PublicKey serverPublicKey, PrivateKey clientPrivateKey) throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(clientPrivateKey);
        keyAgreement.doPhase(serverPublicKey, true);

        byte[] secret = keyAgreement.generateSecret();

        // Use the derived secret as the AES key
        SecretKey aesKey = new SecretKeySpec(secret, "AES");

        return aesKey;
    }

    public static byte[] decrypt(byte[] encryptedBytes, int offset, byte[] secretBytes) {
        try {
            final Cipher aesGcm = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKey key = new SecretKeySpec(secretBytes, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, encryptedBytes, offset, 12);
            aesGcm.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            return aesGcm.doFinal(encryptedBytes, offset + 12, encryptedBytes.length - offset - 12);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] encrypt(byte[] data, byte[] secretKey, byte[] iv, byte[] additionalData) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");

            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmSpec);
            cipher.updateAAD(additionalData);

            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
