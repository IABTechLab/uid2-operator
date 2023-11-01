package com.uid2.operator.service;

import com.uid2.operator.monitoring.TokenResponseStatsCollector;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.store.ISiteStore;
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
        Warning(UIDOperatorVerticle.ResponseStatus.ClientError, 400, rc, message);
    }

    public static void SendErrorResponseAndRecordStats(String errorStatus, int statusCode, RoutingContext rc, String message, Integer siteId, TokenResponseStatsCollector.Endpoint endpoint, TokenResponseStatsCollector.ResponseStatus responseStatus, ISiteStore siteProvider)
    {
        if (statusCode >= 400 && statusCode <= 499) {
            Warning(errorStatus, statusCode, rc, message);
        } else if (statusCode >= 500 && statusCode <= 599) {
            Error(errorStatus, statusCode, rc, message);
            rc.fail(statusCode);
        }
        recordTokenResponseStats(siteId, endpoint, responseStatus, siteProvider);
    }

    public static void SendErrorResponseAndRecordStats(String errorStatus, int statusCode, RoutingContext rc, String message, Integer siteId, TokenResponseStatsCollector.Endpoint endpoint, TokenResponseStatsCollector.ResponseStatus responseStatus, ISiteStore siteProvider, Exception exception)
    {
        if (statusCode >= 400 && statusCode <= 499) {
            Warning(errorStatus, statusCode, rc, message, exception);
        } else if (statusCode >= 500 && statusCode <= 599) {
            Error(errorStatus, statusCode, rc, message, exception);
            rc.fail(statusCode);
        }
        recordTokenResponseStats(siteId, endpoint, responseStatus, siteProvider);
    }

    public static void recordTokenResponseStats(Integer siteId, TokenResponseStatsCollector.Endpoint endpoint, TokenResponseStatsCollector.ResponseStatus responseStatus, ISiteStore siteProvider) {
        TokenResponseStatsCollector.record(siteProvider, siteId, endpoint, responseStatus);
    }

    public static JsonObject Response(String status, String message) {
        final JsonObject json = new JsonObject(new HashMap<>() {
            {
                put("status", status);
            }
        });
        if (message != null) {
            json.put("message", message);
        }
        return json;
    }

    public static void Error(String errorStatus, int statusCode, RoutingContext rc, String message) {
        logError(errorStatus, statusCode, message, new RoutingContextReader(rc), rc.request().remoteAddress().hostAddress());
        final JsonObject json = Response(errorStatus, message);
        rc.response().setStatusCode(statusCode).putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    public static void Error(String errorStatus, int statusCode, RoutingContext rc, String message, Exception exception) {
        logError(errorStatus, statusCode, message, new RoutingContextReader(rc), rc.request().remoteAddress().hostAddress(), exception);
        final JsonObject json = Response(errorStatus, message);
        rc.response().setStatusCode(statusCode).putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    public static void Warning(String status, int statusCode, RoutingContext rc, String message) {
        logWarning(status, statusCode, message, new RoutingContextReader(rc), rc.request().remoteAddress().hostAddress());
        final JsonObject json = Response(status, message);
        rc.response().setStatusCode(statusCode).putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    public static void Warning(String status, int statusCode, RoutingContext rc, String message, Exception exception) {
        logWarning(status, statusCode, message, new RoutingContextReader(rc), rc.request().remoteAddress().hostAddress(), exception);
        final JsonObject json = Response(status, message);
        rc.response().setStatusCode(statusCode).putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    private static void logError(String errorStatus, int statusCode, String message, RoutingContextReader contextReader, String clientAddress) {
        String errorMessage = "Error response to http request. " + JsonObject.of(
                "errorStatus", errorStatus,
                "contact", contextReader.getContact(),
                "siteId", contextReader.getSiteId(),
                "path", contextReader.getPath(),
                "statusCode", statusCode,
                "clientAddress", clientAddress,
                "message", message
        ).encode();
        LOGGER.error(errorMessage);
    }

    private static void logError(String errorStatus, int statusCode, String message, RoutingContextReader contextReader, String clientAddress, Exception exception) {
        String errorMessage = "Error response to http request. " + JsonObject.of(
                "errorStatus", errorStatus,
                "contact", contextReader.getContact(),
                "siteId", contextReader.getSiteId(),
                "path", contextReader.getPath(),
                "statusCode", statusCode,
                "clientAddress", clientAddress,
                "message", message
        ).encode();
        LOGGER.error(errorMessage, exception);
    }

    private static void logWarning(String status, int statusCode, String message, RoutingContextReader contextReader, String clientAddress) {
        String warnMessage = "Warning response to http request. " + JsonObject.of(
                "errorStatus", status,
                "contact", contextReader.getContact(),
                "siteId", contextReader.getSiteId(),
                "path", contextReader.getPath(),
                "statusCode", statusCode,
                "clientAddress", clientAddress,
                "message", message
        ).encode();
        LOGGER.warn(warnMessage);
    }

    private static void logWarning(String status, int statusCode, String message, RoutingContextReader contextReader, String clientAddress, Exception exception) {
        String warnMessage = "Warning response to http request. " + JsonObject.of(
                "errorStatus", status,
                "contact", contextReader.getContact(),
                "siteId", contextReader.getSiteId(),
                "path", contextReader.getPath(),
                "statusCode", statusCode,
                "clientAddress", clientAddress,
                "message", message
        ).encode();
        LOGGER.warn(warnMessage, exception);
    }
}
