package com.uid2.operator.service;

import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.middleware.AuthMiddleware;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;

public class ResponseUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(ResponseUtil.class);

    public static void SuccessNoBody(String status, RoutingContext rc) {
        final JsonObject json = new JsonObject(new HashMap<String, Object>() {
            {
                put("status", status);
            }
        });
        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    public static void Success(RoutingContext rc, Object body) {
        final JsonObject json = new JsonObject(new HashMap<String, Object>() {
            {
                put("status", UIDOperatorVerticle.ResponseStatus.Success);
                put("body", body);
            }
        });
        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    public static void SuccessNoBodyV2(String status, RoutingContext rc) {
        final JsonObject json = new JsonObject(new HashMap<String, Object>() {
            {
                put("status", status);
            }
        });
        rc.data().put("response", json);
    }

    public static void SuccessV2(RoutingContext rc, Object body) {
        final JsonObject json = new JsonObject(new HashMap<String, Object>() {
            {
                put("status", UIDOperatorVerticle.ResponseStatus.Success);
                put("body", body);
            }
        });
        rc.data().put("response", json);
    }

    public static void ClientError(RoutingContext rc, String message) {
        Error(UIDOperatorVerticle.ResponseStatus.ClientError, 400, rc, message);
    }

    public static void Error(String errorStatus, int statusCode, RoutingContext rc, String message) {
        logError(errorStatus, statusCode, rc, message);
        final JsonObject json = new JsonObject(new HashMap<String, Object>() {
            {
                put("status", errorStatus);
            }
        });
        if (message != null) {
            json.put("message", message);
        }
        rc.response().setStatusCode(statusCode).putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());

    }

    private static void logError(String errorStatus, int statusCode, RoutingContext rc, String message) {
        try {
            LOGGER.error(
                    "Error response to http request. { " +
                            "\"errorStatus\": \"{}\", " +
                            "\"contact\": \"{}\", " +
                            "\"path\": \"{}\", " +
                            "\"statusCode\": {}, " +
                            "\"message\": \"{}\" }",
                    errorStatus,
                    safeGetClientKey(rc),
                    rc.request().path(),
                    statusCode,
                    message
            );
        } catch (Exception ignored) {}
    }

    private static String safeGetClientKey(RoutingContext rc) {
        try {
            return AuthMiddleware.getAuthClient(rc).getContact();
        } catch (Exception ignored) {
            return null;
        }
    }

}
