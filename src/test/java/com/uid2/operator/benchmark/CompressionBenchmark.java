package com.uid2.operator.benchmark;

import com.uid2.operator.service.V2RequestUtil;
import com.uid2.shared.Utils;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(1)
public class CompressionBenchmark {

    private static final int EMAIL_COUNT = 10000;
    private JsonObject smallRequest;
    private JsonObject largeRequest;
    private JsonObject smallResponse;
    private JsonObject largeResponse;
    
    private byte[] smallRequestBytes;
    private byte[] largeRequestBytes;
    private byte[] smallResponseBytes;
    private byte[] largeResponseBytes;
    
    private byte[] compressedSmallRequest;
    private byte[] compressedLargeRequest;
    private byte[] compressedSmallResponse;
    private byte[] compressedLargeResponse;

    @Setup
    public void setup() throws Exception {
        // Generate test emails
        List<String> emails = generateTestEmails(EMAIL_COUNT);
        
        // Create small request (single email)
        smallRequest = new JsonObject()
            .put("email", emails.get(0))
            .put("timestamp", System.currentTimeMillis());
            
        // Create large request (batch of emails)
        JsonArray emailArray = new JsonArray();
        emails.forEach(emailArray::add);
        largeRequest = new JsonObject()
            .put("emails", emailArray)
            .put("timestamp", System.currentTimeMillis())
            .put("batch_size", EMAIL_COUNT);
            
        // Create small response (single token)
        smallResponse = new JsonObject()
            .put("status", "success")
            .put("body", new JsonObject()
                .put("advertising_token", generateMockToken())
                .put("refresh_token", generateMockRefreshToken())
                .put("identity_expires", System.currentTimeMillis() + 3600000)
                .put("refresh_expires", System.currentTimeMillis() + 7200000));
                
        // Create large response (batch of tokens)
        JsonArray tokenArray = new JsonArray();
        for (int i = 0; i < EMAIL_COUNT; i++) {
            tokenArray.add(new JsonObject()
                .put("advertising_token", generateMockToken())
                .put("refresh_token", generateMockRefreshToken())
                .put("identity_expires", System.currentTimeMillis() + 3600000)
                .put("refresh_expires", System.currentTimeMillis() + 7200000));
        }
        largeResponse = new JsonObject()
            .put("status", "success")
            .put("body", new JsonObject()
                .put("tokens", tokenArray)
                .put("processed_count", EMAIL_COUNT));
        
        // Convert to bytes
        smallRequestBytes = smallRequest.encode().getBytes(StandardCharsets.UTF_8);
        largeRequestBytes = largeRequest.encode().getBytes(StandardCharsets.UTF_8);
        smallResponseBytes = smallResponse.encode().getBytes(StandardCharsets.UTF_8);
        largeResponseBytes = largeResponse.encode().getBytes(StandardCharsets.UTF_8);
        
        // Pre-compress for decompression benchmarks
        compressedSmallRequest = V2RequestUtil.compressPayload(smallRequestBytes);
        compressedLargeRequest = V2RequestUtil.compressPayload(largeRequestBytes);
        compressedSmallResponse = V2RequestUtil.compressPayload(smallResponseBytes);
        compressedLargeResponse = V2RequestUtil.compressPayload(largeResponseBytes);
        
        // Print size comparison
        printSizeComparison();
    }
    
    private void printSizeComparison() {
        System.out.println("=== Compression Size Analysis ===");
        System.out.printf("Small Request: %d bytes -> %d bytes (%.1f%% reduction)%n",
            smallRequestBytes.length, compressedSmallRequest.length,
            (1.0 - (double)compressedSmallRequest.length / smallRequestBytes.length) * 100);
        System.out.printf("Large Request: %d bytes -> %d bytes (%.1f%% reduction)%n",
            largeRequestBytes.length, compressedLargeRequest.length,
            (1.0 - (double)compressedLargeRequest.length / largeRequestBytes.length) * 100);
        System.out.printf("Small Response: %d bytes -> %d bytes (%.1f%% reduction)%n",
            smallResponseBytes.length, compressedSmallResponse.length,
            (1.0 - (double)compressedSmallResponse.length / smallResponseBytes.length) * 100);
        System.out.printf("Large Response: %d bytes -> %d bytes (%.1f%% reduction)%n",
            largeResponseBytes.length, compressedLargeResponse.length,
            (1.0 - (double)compressedLargeResponse.length / largeResponseBytes.length) * 100);
        System.out.println("=================================");
    }

    // Compression benchmarks
    @Benchmark
    public void compressSmallRequest(Blackhole bh) {
        bh.consume(V2RequestUtil.compressPayload(smallRequestBytes));
    }
    
    @Benchmark
    public void compressLargeRequest(Blackhole bh) {
        bh.consume(V2RequestUtil.compressPayload(largeRequestBytes));
    }
    
    @Benchmark
    public void compressSmallResponse(Blackhole bh) {
        bh.consume(V2RequestUtil.compressPayload(smallResponseBytes));
    }
    
    @Benchmark
    public void compressLargeResponse(Blackhole bh) {
        bh.consume(V2RequestUtil.compressPayload(largeResponseBytes));
    }

    // Decompression benchmarks
    @Benchmark
    public void decompressSmallRequest(Blackhole bh) {
        bh.consume(V2RequestUtil.decompressPayload(compressedSmallRequest));
    }
    
    @Benchmark
    public void decompressLargeRequest(Blackhole bh) {
        bh.consume(V2RequestUtil.decompressPayload(compressedLargeRequest));
    }
    
    @Benchmark
    public void decompressSmallResponse(Blackhole bh) {
        bh.consume(V2RequestUtil.decompressPayload(compressedSmallResponse));
    }
    
    @Benchmark
    public void decompressLargeResponse(Blackhole bh) {
        bh.consume(V2RequestUtil.decompressPayload(compressedLargeResponse));
    }

    // Utility methods
    private List<String> generateTestEmails(int count) throws Exception {
        List<String> emails = new ArrayList<>();
        Random random = new Random(12345); // Fixed seed for reproducibility
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        
        for (int i = 0; i < count; i++) {
            // Generate diverse email patterns
            String email;
            if (i % 5 == 0) {
                // Corporate emails
                email = String.format("user%d@company%d.com", i, i % 100);
            } else if (i % 5 == 1) {
                // Gmail pattern
                email = String.format("test.user.%d@gmail.com", i);
            } else if (i % 5 == 2) {
                // Random domain
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
        // Generate a realistic-looking advertising token
        byte[] tokenBytes = new byte[164]; // Typical V3 token size
        new Random().nextBytes(tokenBytes);
        return Utils.toBase64String(tokenBytes);
    }
    
    private String generateMockRefreshToken() {
        // Generate a realistic-looking refresh token
        byte[] tokenBytes = new byte[124]; // Typical V3 refresh token size
        new Random().nextBytes(tokenBytes);
        return Utils.toBase64String(tokenBytes);
    }
}