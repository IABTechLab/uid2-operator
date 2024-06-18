package com.uid2.operator.service;

public class ShutdownService {
    public void Shutdown(int status) {
        System.exit(status);

        // according to the docks, this should not be reached as System.exit does not complete either normally or abruptly.
        // Added for safety
        throw new RuntimeException("JVM Requested to shut down");
    }
}