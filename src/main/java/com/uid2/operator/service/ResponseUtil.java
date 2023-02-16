package com.uid2.operator.service;

import com.uid2.operator.vertx.UIDOperatorVerticle;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

import java.util.HashMap;

public class ResponseUtil {
    public static void SuccessNoBody(String status, RoutingContext ctx) {
        final JsonObject json = new JsonObject(new HashMap<String, Object>() {
            {
                put("status", status);
            }
        });
        ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
            .end(json.encode());
    }

    public static void Success(RoutingContext ctx, Object body) {
        final JsonObject json = new JsonObject(new HashMap<String, Object>() {
            {
                put("status", UIDOperatorVerticle.ResponseStatus.Success);
                put("body", body);
            }
        });
        ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
            .end(json.encode());
    }

    public static void SuccessNoBodyV2(String status, RoutingContext ctx) {
        final JsonObject json = new JsonObject(new HashMap<String, Object>() {
            {
                put("status", status);
            }
        });
        ctx.data().put("response", json);
    }

    public static void SuccessV2(RoutingContext ctx, Object body) {
        final JsonObject json = new JsonObject(new HashMap<String, Object>() {
            {
                put("status", UIDOperatorVerticle.ResponseStatus.Success);
                put("body", body);
            }
        });
        ctx.data().put("response", json);
    }

    public static void OptOutV2(RoutingContext ctx, Object body) {
        final JsonObject json = new JsonObject(new HashMap<String, Object>() {
            {
                put("status", UIDOperatorVerticle.ResponseStatus.OptOut);
                put("body", body);
            }
        });
        ctx.data().put("response", json);
    }

    public static void ClientError(RoutingContext ctx, String message) {
        Error(UIDOperatorVerticle.ResponseStatus.ClientError, 400, ctx, message);
    }

    public static void Error(String errorStatus, int statusCode, RoutingContext ctx, String message) {
        final JsonObject json = new JsonObject(new HashMap<String, Object>() {
            {
                put("status", errorStatus);
            }
        });
        if (message != null) {
            json.put("message", message);
        }
        ctx.response().setStatusCode(statusCode).putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
            .end(json.encode());
    }
}
