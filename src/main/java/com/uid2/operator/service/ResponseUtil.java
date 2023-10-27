package com.uid2.operator.service;

import com.uid2.operator.vertx.UIDOperatorVerticle;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;

public class ResponseUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(ResponseUtil.class);

    public static void SuccessNoBody(String status, RoutingContext rc) {
        final JsonObject json = new JsonObject(new HashMap<>() {
            {
                put("status", status);
            }
        });
        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    public static void Success(RoutingContext rc, Object body) {
        final JsonObject json = new JsonObject(new HashMap<>() {
            {
                put("status", UIDOperatorVerticle.ResponseStatus.Success);
                put("body", body);
            }
        });
        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    public static void SuccessNoBodyV2(String status, RoutingContext rc) {
        final JsonObject json = new JsonObject(new HashMap<>() {
            {
                put("status", status);
            }
        });
        rc.data().put("response", json);
    }

    public static JsonObject SuccessV2(Object body) {
        return new JsonObject(new HashMap<>() {
            {
                put("status", UIDOperatorVerticle.ResponseStatus.Success);
                put("body", body);
            }
        });
    }

    public static void SuccessV2(RoutingContext rc, Object body) {
        final JsonObject json = SuccessV2(body);
        rc.data().put("response", json);
    }

    public static void ClientError(RoutingContext rc, String message) {
        Error(UIDOperatorVerticle.ResponseStatus.ClientError, 400, rc, message);
    }

    public static JsonObject Error(String errorStatus, String message) {
        final JsonObject json = new JsonObject(new HashMap<>() {
            {
                put("status", errorStatus);
            }
        });
        if (message != null) {
            json.put("message", message);
        }
        return json;
    }

    public static void Error(String errorStatus, int statusCode, RoutingContext rc, String message) {
        logError(errorStatus, statusCode, message, new RoutingContextReader(rc), rc.request().remoteAddress().hostAddress());
        final JsonObject json = Error(errorStatus, message);
        rc.response().setStatusCode(statusCode).putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }


    private static void logError(String errorStatus, int statusCode, String message, RoutingContextReader contextReader, String clientAddress) {
        JsonObject errorJsonObj = JsonObject.of(
                "errorStatus", errorStatus,
                "contact", contextReader.getContact(),
                "siteId", contextReader.getSiteId(),
                "path", contextReader.getPath(),
                "statusCode", statusCode,
                "clientAddress", clientAddress,
                "message", message
        );
        final String linkName = contextReader.getLinkName();
        if (!linkName.isBlank()) {
            errorJsonObj.put(SecureLinkValidatorService.LINK_NAME, linkName);
        }
        final String serviceName = contextReader.getServiceName();
        if (!serviceName.isBlank()) {
            errorJsonObj.put(SecureLinkValidatorService.SERVICE_NAME, serviceName);
        }
        LOGGER.error("Error response to http request. " + errorJsonObj.encode());
    }
}
