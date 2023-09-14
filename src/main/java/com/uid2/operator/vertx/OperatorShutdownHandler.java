package com.uid2.operator.vertx;

import com.uid2.shared.middleware.AuthMiddleware;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.utils.Pair;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

public class OperatorShutdownHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(OperatorShutdownHandler.class);
    private final Duration shutdownWaitTime;
    private AtomicReference<Instant> failureStartTime = new AtomicReference<>(null);
    private final Clock clock;

    public OperatorShutdownHandler(Duration shutdownWaitTime, Clock clock) {
        this.shutdownWaitTime = shutdownWaitTime;
        this.clock = clock;
    }


    public void handleResponse(Pair<Integer, String> response) {
        if (response.right().equals("Unauthorized")) {
            LOGGER.error("core attestation failed due to invalid operator key. shutting down operator");
            System.exit(1);
        } else {
            try {
                JsonObject respJson = new JsonObject(response.right());
                if (respJson.equals(AuthMiddleware.UnauthorizedResponse)) {
                    LOGGER.error("core attestation failed due to invalid operator key. shutting down operator");
                    System.exit(1);
                }else if(respJson.equals(new JsonObject().put("status", "The enclave identifier is unknown"))) {
                    LOGGER.error("core attestation failed due to unknown enclave identifier. shutting down operator");
                    System.exit(1);
                }
            } catch (DecodeException ignored) {

            }
        }
        if (response.left() == 200) {
            failureStartTime.set(null);
        } else {
            Instant t = failureStartTime.get();
            if (t == null) {
                failureStartTime.set(clock.instant());
            } else if (Duration.between(t, clock.instant()).compareTo(this.shutdownWaitTime) > 0) {
                LOGGER.error("core attestation has been in failed state for too long. shutting down operator");
                System.exit(1);
            }
        }
    }
}
