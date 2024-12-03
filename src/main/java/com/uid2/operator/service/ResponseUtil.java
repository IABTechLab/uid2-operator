package com.uid2.operator.service;

import com.uid2.operator.monitoring.TokenResponseStatsCollector;
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

    public static void LogInfoAndSend400Response(RoutingContext rc, String message) {
        LogInfoAndSendResponse(ResponseStatus.ClientError, 400, rc, message);
    }

    public static void SendClientErrorResponseAndRecordStats(String errorStatus, int statusCode, RoutingContext rc, String message, Integer siteId, TokenResponseStatsCollector.Endpoint endpoint, TokenResponseStatsCollector.ResponseStatus responseStatus, ISiteStore siteProvider, TokenResponseStatsCollector.PlatformType platformType)
    {
        // 400 error
        if (ResponseStatus.ClientError.equals(errorStatus))
        {
            LogInfoAndSendResponse(errorStatus, statusCode, rc, message);
        }
        // 4xx error other than 400
        else {
            LogWarningAndSendResponse(errorStatus, statusCode, rc, message);
        }

        recordTokenResponseStats(siteId, endpoint, responseStatus, siteProvider, null, platformType);
    }

    public static void SendServerErrorResponseAndRecordStats(RoutingContext rc, String message, Integer siteId, TokenResponseStatsCollector.Endpoint endpoint, TokenResponseStatsCollector.ResponseStatus responseStatus, ISiteStore siteProvider, Exception exception, TokenResponseStatsCollector.PlatformType platformType)
    {
        LogErrorAndSendResponse(ResponseStatus.UnknownError, 500, rc, message, exception);
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

    public static void LogErrorAndSendResponse(String errorStatus, int statusCode, RoutingContext rc, String message) {
        String msg = ComposeMessage(errorStatus, statusCode, message, new RoutingContextReader(rc), rc.request().remoteAddress().hostAddress());
        LOGGER.error(msg);
        final JsonObject json = Response(errorStatus, message);
        rc.response().setStatusCode(statusCode).putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    public static void LogErrorAndSendResponse(String errorStatus, int statusCode, RoutingContext rc, String message, Exception exception) {
        String msg = ComposeMessage(errorStatus, statusCode, message, new RoutingContextReader(rc), rc.request().remoteAddress().hostAddress());
        LOGGER.error(msg, exception);
        final JsonObject json = Response(errorStatus, message);
        rc.response().setStatusCode(statusCode).putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    public static void LogInfoAndSendResponse(String status, int statusCode, RoutingContext rc, String message) {
        String msg = ComposeMessage(status, statusCode, message, new RoutingContextReader(rc), rc.request().remoteAddress().hostAddress());
        LOGGER.info(msg);
        final JsonObject json = Response(status, message);
        rc.response().setStatusCode(statusCode).putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    public static void LogWarningAndSendResponse(String status, int statusCode, RoutingContext rc, String message) {
        String msg = ComposeMessage(status, statusCode, message, new RoutingContextReader(rc), rc.request().remoteAddress().hostAddress());
        LOGGER.warn(msg);
        final JsonObject json = Response(status, message);
        rc.response().setStatusCode(statusCode).putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(json.encode());
    }

    private static String ComposeMessage(String status, int statusCode, String message, RoutingContextReader contextReader, String clientAddress) {
        JsonObject msgJsonObject = JsonObject.of(
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
                msgJsonObject.put("referer", referer);
            }
            if (origin != null) {
                msgJsonObject.put("origin", origin);
            }
        }

        final String linkName = contextReader.getLinkName();
        if (!linkName.isBlank()) {
            msgJsonObject.put(SecureLinkValidatorService.SERVICE_LINK_NAME, linkName);
        }
        final String serviceName = contextReader.getServiceName();
        if (!serviceName.isBlank()) {
            msgJsonObject.put(SecureLinkValidatorService.SERVICE_NAME, serviceName);
        }
        return "Response to http request. " + msgJsonObject.encode();
    }

    public static class ResponseStatus {
        public static final String Success = "success";
        public static final String Unauthorized = "unauthorized";
        public static final String ClientError = "client_error";
        public static final String OptOut = "optout";
        public static final String InvalidToken = "invalid_token";
        public static final String ExpiredToken = "expired_token";
        public static final String GenericError = "error";
        public static final String InvalidClient = "invalid_client";
        public static final String UnknownError = "unknown";
        public static final String InsufficientUserConsent = "insufficient_user_consent";
        public static final String InvalidHttpOrigin = "invalid_http_origin";
        public static final String InvalidAppName = "invalid_app_name";
    }
}
