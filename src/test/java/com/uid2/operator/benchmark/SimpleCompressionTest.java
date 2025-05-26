package com.uid2.operator.benchmark;

import com.uid2.operator.service.V2RequestUtil;
import com.uid2.shared.Utils;

import java.nio.charset.StandardCharsets;
import java.util.Random;

/**
 * Simple compression test showing V2 envelope comparison without dependencies
 */
public class SimpleCompressionTest {
    
    public static void main(String[] args) {
        System.out.println("=== V2 Envelope Compression Analysis ===");
        System.out.println();
        
        // Test different payload sizes
        testPayload("Small Request (single email)", createSmallPayload());
        testPayload("Medium Request (100 emails)", createMediumPayload());  
        testPayload("Large Request (1000 emails)", createLargePayload());
        testPayload("Very Large Request (5000 emails)", createVeryLargePayload());
    }
    
    private static void testPayload(String description, String payload) {
        System.out.println("--- " + description + " ---");
        
        // Create V2 envelopes with and without compression
        String uncompressedEnvelope = createV2Envelope(payload, false);
        String compressedEnvelope = createV2Envelope(payload, true);
        
        int uncompressedSize = uncompressedEnvelope.length();
        int compressedSize = compressedEnvelope.length();
        
        double reduction = (1.0 - (double)compressedSize / uncompressedSize) * 100;
        
        System.out.printf("Raw payload: %,6d bytes%n", payload.length());
        System.out.printf("V2 envelope (uncompressed): %,6d bytes%n", uncompressedSize);
        System.out.printf("V2 envelope (compressed):   %,6d bytes%n", compressedSize);
        System.out.printf("Envelope reduction: %.1f%% (%,d bytes saved)%n", 
            reduction, uncompressedSize - compressedSize);
        
        // Bandwidth savings
        long monthlySavings = (long)(uncompressedSize - compressedSize) * 1_000_000L * 30L / (1024 * 1024);
        System.out.printf("Bandwidth savings (1M requests/day): %,d MB/month%n", monthlySavings);
        System.out.println();
    }
    
    private static String createV2Envelope(String payload, boolean compress) {
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        
        // Apply compression if requested
        if (compress) {
            payloadBytes = V2RequestUtil.compressPayload(payloadBytes);
        }
        
        // Simulate encryption overhead (16-byte auth tag + padding)
        int encryptionOverhead = 16 + (16 - (payloadBytes.length % 16)) % 16;
        byte[] encryptedPayload = new byte[payloadBytes.length + encryptionOverhead];
        System.arraycopy(payloadBytes, 0, encryptedPayload, 0, payloadBytes.length);
        
        // Fill overhead with mock data
        Random rand = new Random(42); // Fixed seed for consistent results
        for (int i = payloadBytes.length; i < encryptedPayload.length; i++) {
            encryptedPayload[i] = (byte) rand.nextInt(256);
        }
        
        // Create V2 envelope with base64 encoded payload
        String base64Payload = Utils.toBase64String(encryptedPayload);
        return "{\"status\":\"success\",\"body\":\"" + base64Payload + "\"}";
    }
    
    private static String createSmallPayload() {
        return "{\"email\":\"user@example.com\",\"timestamp\":" + System.currentTimeMillis() + ",\"policy\":1}";
    }
    
    private static String createMediumPayload() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"emails\":[");
        for (int i = 0; i < 100; i++) {
            if (i > 0) sb.append(",");
            sb.append("\"user").append(i).append("@example.com\"");
        }
        sb.append("],\"timestamp\":").append(System.currentTimeMillis()).append(",\"policy\":1}");
        return sb.toString();
    }
    
    private static String createLargePayload() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"emails\":[");
        for (int i = 0; i < 1000; i++) {
            if (i > 0) sb.append(",");
            sb.append("\"user").append(i).append("@company").append(i % 20).append(".com\"");
        }
        sb.append("],\"timestamp\":").append(System.currentTimeMillis()).append(",\"policy\":1,\"batch_size\":1000}");
        return sb.toString();
    }
    
    private static String createVeryLargePayload() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"emails\":[");
        for (int i = 0; i < 5000; i++) {
            if (i > 0) sb.append(",");
            sb.append("\"very.long.email.address.").append(i).append("@verylongdomainname").append(i % 50).append(".com\"");
        }
        sb.append("],\"timestamp\":").append(System.currentTimeMillis()).append(",\"policy\":1,\"batch_size\":5000}");
        return sb.toString();
    }
}