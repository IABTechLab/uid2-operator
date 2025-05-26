package com.uid2.operator.benchmark;

import com.uid2.operator.service.V2RequestUtil;
import com.uid2.shared.Utils;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Standalone compression analysis tool for v2 payload compression.
 * Provides detailed size comparisons and compression ratios for FULL V2 ENVELOPES.
 * This compares the actual encrypted envelope sizes that get transmitted over the wire.
 */
public class CompressionAnalysis {
    
    private static final int EMAIL_COUNT = 10000;
    
    public static void main(String[] args) throws Exception {
        CompressionAnalysis analysis = new CompressionAnalysis();
        analysis.runAnalysis();
    }
    
    public void runAnalysis() throws Exception {
        System.out.println("=== UID2 V2 Payload Compression Analysis ===");
        System.out.printf("Testing with %d emails%n", EMAIL_COUNT);
        System.out.println();
        
        // Generate test data
        List<String> emails = generateTestEmails(EMAIL_COUNT);
        
        // Test different payload sizes
        analyzePayloadType("Single Email Request", createSingleEmailRequest(emails.get(0)));
        analyzePayloadType("Batch Request (100 emails)", createBatchRequest(emails.subList(0, 100)));
        analyzePayloadType("Batch Request (1000 emails)", createBatchRequest(emails.subList(0, 1000)));
        analyzePayloadType("Large Batch Request (10000 emails)", createBatchRequest(emails));
        
        analyzePayloadType("Single Token Response", createSingleTokenResponse());
        analyzePayloadType("Batch Token Response (100 tokens)", createBatchTokenResponse(100));
        analyzePayloadType("Batch Token Response (1000 tokens)", createBatchTokenResponse(1000));
        analyzePayloadType("Large Batch Token Response (10000 tokens)", createBatchTokenResponse(10000));
        
        // Test different content types
        System.out.println("=== Content Type Analysis ===");
        analyzeContentTypes();
        
        // Performance analysis
        System.out.println("=== Performance Analysis ===");
        performanceAnalysis(emails);
    }
    
    private void analyzePayloadType(String description, JsonObject payload) {
        System.out.println("\n--- " + description + " ---");
        
        // Create V2 envelopes with and without compression
        String uncompressedEnvelope = createMockV2Envelope(payload, false);
        String compressedEnvelope = createMockV2Envelope(payload, true);
        
        byte[] uncompressedBytes = uncompressedEnvelope.getBytes(StandardCharsets.UTF_8);
        byte[] compressedBytes = compressedEnvelope.getBytes(StandardCharsets.UTF_8);
        
        double compressionRatio = (double) compressedBytes.length / uncompressedBytes.length;
        double spaceSavings = (1.0 - compressionRatio) * 100;
        
        System.out.printf("Raw payload size: %8d bytes%n", payload.encode().length());
        System.out.printf("V2 envelope (uncompressed): %8d bytes%n", uncompressedBytes.length);
        System.out.printf("V2 envelope (compressed):   %8d bytes%n", compressedBytes.length);
        System.out.printf("Total envelope reduction: %8.1f%% (%.2fx ratio)%n", spaceSavings, 1.0/compressionRatio);
        
        // Show bandwidth savings for different request volumes
        long dailyRequests = 1_000_000; // 1M requests per day
        long monthlySavingsMB = (uncompressedBytes.length - compressedBytes.length) * dailyRequests * 30 / (1024 * 1024);
        System.out.printf("Bandwidth savings (1M req/day): %d MB/month%n", monthlySavingsMB);
    }
    
    /**
     * Creates a mock V2 envelope that simulates the full encrypted response structure
     */
    private String createMockV2Envelope(JsonObject payload, boolean useCompression) {
        byte[] payloadBytes = payload.encode().getBytes(StandardCharsets.UTF_8);
        
        // Apply compression if requested
        if (useCompression) {
            payloadBytes = V2RequestUtil.compressPayload(payloadBytes);
        }
        
        // Mock encryption (simulate AES-GCM overhead)
        byte[] mockEncryptedPayload = simulateEncryption(payloadBytes);
        String base64EncryptedPayload = Utils.toBase64String(mockEncryptedPayload);
        
        // Create V2 envelope structure
        JsonObject envelope = new JsonObject()
            .put("body", base64EncryptedPayload)
            .put("status", "success");
            
        return envelope.encode();
    }
    
    /**
     * Simulates AES-GCM encryption overhead (16-byte auth tag + IV overhead)
     */
    private byte[] simulateEncryption(byte[] plaintext) {
        // AES-GCM adds: 16-byte auth tag + some padding
        int overhead = 16 + (16 - (plaintext.length % 16)) % 16; // Auth tag + padding
        byte[] encrypted = new byte[plaintext.length + overhead];
        
        // Copy original data (in real encryption this would be encrypted)
        System.arraycopy(plaintext, 0, encrypted, 0, plaintext.length);
        
        // Fill overhead bytes with random data to simulate auth tag
        Random rand = new Random();
        for (int i = plaintext.length; i < encrypted.length; i++) {
            encrypted[i] = (byte) rand.nextInt(256);
        }
        
        return encrypted;
    }
    
    private void analyzeContentTypes() {
        // Highly repetitive content (should compress very well)
        JsonObject repetitive = new JsonObject();
        JsonArray repeatArray = new JsonArray();
        for (int i = 0; i < 1000; i++) {
            repeatArray.add("repeated_value_" + (i % 10)); // Only 10 unique values
        }
        repetitive.put("data", repeatArray);
        analyzePayloadType("Highly Repetitive Content", repetitive);
        
        // Random content (should compress poorly)
        JsonObject random = new JsonObject();
        JsonArray randomArray = new JsonArray();
        Random rand = new Random();
        for (int i = 0; i < 1000; i++) {
            byte[] randomBytes = new byte[32];
            rand.nextBytes(randomBytes);
            randomArray.add(Utils.toBase64String(randomBytes));
        }
        random.put("data", randomArray);
        analyzePayloadType("Random Content", random);
        
        // Mixed content (realistic scenario)
        JsonObject mixed = new JsonObject();
        JsonArray mixedArray = new JsonArray();
        for (int i = 0; i < 1000; i++) {
            JsonObject item = new JsonObject()
                .put("id", i)
                .put("email", "user" + (i % 100) + "@domain" + (i % 20) + ".com")
                .put("timestamp", System.currentTimeMillis())
                .put("status", "active")
                .put("token", generateMockToken());
            mixedArray.add(item);
        }
        mixed.put("data", mixedArray);
        analyzePayloadType("Mixed Content (Realistic)", mixed);
    }
    
    private void performanceAnalysis(List<String> emails) throws Exception {
        JsonObject largePayload = createBatchRequest(emails);
        byte[] payloadBytes = largePayload.encode().getBytes(StandardCharsets.UTF_8);
        
        // Compression performance
        int iterations = 100;
        long startTime = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            V2RequestUtil.compressPayload(payloadBytes);
        }
        long compressionTime = System.nanoTime() - startTime;
        
        // Decompression performance
        byte[] compressed = V2RequestUtil.compressPayload(payloadBytes);
        startTime = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            V2RequestUtil.decompressPayload(compressed);
        }
        long decompressionTime = System.nanoTime() - startTime;
        
        System.out.printf("Compression   (avg of %d): %.2f ms%n", iterations, compressionTime / 1_000_000.0 / iterations);
        System.out.printf("Decompression (avg of %d): %.2f ms%n", iterations, decompressionTime / 1_000_000.0 / iterations);
        System.out.printf("Payload size: %d bytes%n", payloadBytes.length);
        System.out.printf("Throughput - Compression: %.2f MB/s%n", 
            (payloadBytes.length * iterations / 1_000_000.0) / (compressionTime / 1_000_000_000.0));
        System.out.printf("Throughput - Decompression: %.2f MB/s%n",
            (payloadBytes.length * iterations / 1_000_000.0) / (decompressionTime / 1_000_000_000.0));
    }
    
    private JsonObject createSingleEmailRequest(String email) {
        return new JsonObject()
            .put("email", email)
            .put("timestamp", System.currentTimeMillis())
            .put("policy", 1);
    }
    
    private JsonObject createBatchRequest(List<String> emails) {
        JsonArray emailArray = new JsonArray();
        emails.forEach(emailArray::add);
        
        return new JsonObject()
            .put("emails", emailArray)
            .put("timestamp", System.currentTimeMillis())
            .put("policy", 1)
            .put("batch_size", emails.size());
    }
    
    private JsonObject createSingleTokenResponse() {
        return new JsonObject()
            .put("status", "success")
            .put("body", new JsonObject()
                .put("advertising_token", generateMockToken())
                .put("refresh_token", generateMockRefreshToken())
                .put("identity_expires", System.currentTimeMillis() + 3600000)
                .put("refresh_expires", System.currentTimeMillis() + 7200000)
                .put("refresh_from", System.currentTimeMillis() + 1800000)
                .put("refresh_response_key", Utils.toBase64String(new byte[32])));
    }
    
    private JsonObject createBatchTokenResponse(int tokenCount) {
        JsonArray tokenArray = new JsonArray();
        for (int i = 0; i < tokenCount; i++) {
            tokenArray.add(new JsonObject()
                .put("advertising_token", generateMockToken())
                .put("refresh_token", generateMockRefreshToken())
                .put("identity_expires", System.currentTimeMillis() + 3600000)
                .put("refresh_expires", System.currentTimeMillis() + 7200000)
                .put("refresh_from", System.currentTimeMillis() + 1800000)
                .put("refresh_response_key", Utils.toBase64String(new byte[32])));
        }
        
        return new JsonObject()
            .put("status", "success")
            .put("body", new JsonObject()
                .put("tokens", tokenArray)
                .put("processed_count", tokenCount)
                .put("timestamp", System.currentTimeMillis()));
    }
    
    public List<String> generateTestEmails(int count) throws Exception {
        List<String> emails = new ArrayList<>();
        Random random = new Random(12345); // Fixed seed for reproducibility
        
        for (int i = 0; i < count; i++) {
            String email;
            if (i % 5 == 0) {
                // Corporate emails (common pattern)
                email = String.format("user%d@company%d.com", i, i % 100);
            } else if (i % 5 == 1) {
                // Gmail pattern (very common)
                email = String.format("test.user.%d@gmail.com", i);
            } else if (i % 5 == 2) {
                // Various domains
                email = String.format("person%d@domain%d.org", i, random.nextInt(50));
            } else if (i % 5 == 3) {
                // Long email addresses
                email = String.format("very.long.email.address.for.testing.purposes.%d@verylongdomainname%d.net", i, i % 20);
            } else {
                // Short emails
                email = String.format("u%d@d%d.co", i, i % 10);
            }
            emails.add(email);
        }
        
        return emails;
    }
    
    private String generateMockToken() {
        // Generate a realistic V3 advertising token
        byte[] tokenBytes = new byte[164];
        new Random().nextBytes(tokenBytes);
        return Utils.toBase64String(tokenBytes);
    }
    
    private String generateMockRefreshToken() {
        // Generate a realistic V3 refresh token
        byte[] tokenBytes = new byte[124];
        new Random().nextBytes(tokenBytes);
        return Utils.toBase64String(tokenBytes);
    }
}