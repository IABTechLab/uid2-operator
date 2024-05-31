package com.uid2.operator.service;

import com.uid2.operator.monitoring.TokenResponseStatsCollector;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.model.TokenVersion;
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
                put("status", ResponseStatus.Success);
                put("body", body);
            }
        });
        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    public static JsonObject SuccessNoBodyV2(String status) {
        final JsonObject json = new JsonObject(new HashMap<>() {
            {
                put("status", status);
            }
        });
        return json;
    }

    public static void SuccessNoBodyV2(String status, RoutingContext rc) {
        final JsonObject json = SuccessNoBodyV2(status);
        rc.data().put("response", json);
    }

    public static JsonObject SuccessV2(Object body) {
        return new JsonObject(new HashMap<>() {
            {
                put("status", ResponseStatus.Success);
                put("body", body);
            }
        });
    }

    public static void SuccessV2(RoutingContext rc, Object body) {
        final JsonObject json = SuccessV2(body);
        rc.data().put("response", json);
    }

    public static void ClientError(RoutingContext rc, String message) {
        Warning(ResponseStatus.ClientError, 400, rc, message);
    }

    public static void SendClientErrorResponseAndRecordStats(String errorStatus, int statusCode, RoutingContext rc, String message, Integer siteId, TokenResponseStatsCollector.Endpoint endpoint, TokenResponseStatsCollector.ResponseStatus responseStatus, ISiteStore siteProvider, TokenResponseStatsCollector.PlatformType platformType)
    {
        Warning(errorStatus, statusCode, rc, message);
        recordTokenResponseStats(siteId, endpoint, responseStatus, siteProvider, null, platformType);
    }

    public static void SendServerErrorResponseAndRecordStats(RoutingContext rc, String message, Integer siteId, TokenResponseStatsCollector.Endpoint endpoint, TokenResponseStatsCollector.ResponseStatus responseStatus, ISiteStore siteProvider, Exception exception, TokenResponseStatsCollector.PlatformType platformType)
    {
        Error(ResponseStatus.UnknownError, 500, rc, message, exception);
        rc.fail(500);
        recordTokenResponseStats(siteId, endpoint, responseStatus, siteProvider, null, platformType);
    }

    public static void recordTokenResponseStats(Integer siteId, TokenResponseStatsCollector.Endpoint endpoint, TokenResponseStatsCollector.ResponseStatus responseStatus, ISiteStore siteProvider, TokenVersion advertisingTokenVersion, TokenResponseStatsCollector.PlatformType platformType) {
        TokenResponseStatsCollector.record(siteProvider, siteId, endpoint, advertisingTokenVersion, responseStatus, platformType);
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

    private static void logError(String errorStatus, int statusCode, String message, RoutingContextReader contextReader, String clientAddress) {
        JsonObject errorJsonObj = JsonObject.of(
                "errorStatus", errorStatus,
                "contact", contextReader.getContact(),
                "siteId", contextReader.getSiteId(),
                "statusCode", statusCode,
                "clientAddress", clientAddress,
                "message", message
        );
        final String linkName = contextReader.getLinkName();
        if (!linkName.isBlank()) {
            errorJsonObj.put(SecureLinkValidatorService.SERVICE_LINK_NAME, linkName);
        }
        final String serviceName = contextReader.getServiceName();
        if (!serviceName.isBlank()) {
            errorJsonObj.put(SecureLinkValidatorService.SERVICE_NAME, serviceName);
        }
        LOGGER.error("Error response to http request. " + errorJsonObj.encode());
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
        JsonObject warnMessageJsonObject = JsonObject.of(
                "errorStatus", status,
                "contact", contextReader.getContact(),
                "siteId", contextReader.getSiteId(),
                "path", contextReader.getPath(),
                "statusCode", statusCode,
                "clientAddress", clientAddress,
                "message", message
        );
        final String referer = contextReader.getReferer();
        final String origin = contextReader.getOrigin();
        if (statusCode >= 400 && statusCode < 500) {
            if (referer != null) {
                warnMessageJsonObject.put("referer", referer);
            }
            if (origin != null) {
                warnMessageJsonObject.put("origin", origin);
            }
        }
        String warnMessage = "Warning response to http request. " + warnMessageJsonObject.encode();
        LOGGER.warn(warnMessage);
    }

    public static class ResponseStatus {
        public static final String Success = "success";
        public static final String Unauthorized = "unauthorized";
        public static final String ClientError = "client_error";
        public static final String OptOut = "optout";
        public static final String InvalidToken = "invalid_token";
        public static final String ExpiredToken = "expired_token";
        public static final String GenericError = "error";
        public static final String UnknownError = "unknown";
        public static final String InsufficientUserConsent = "insufficient_user_consent";
        public static final String InvalidHttpOrigin = "invalid_http_origin";
        public static final String InvalidAppName = "invalid_app_name";
    }
}
