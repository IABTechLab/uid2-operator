package com.uid2.operator.service;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

public class JsonParseUtils {
    public static JsonArray parseArray(JsonObject object, String key, RoutingContext rc) {
        JsonArray outArray;
        try {
            outArray = object.getJsonArray(key);
        } catch (ClassCastException e) {
            ResponseUtil.ClientError(rc, String.format("%s must be an array", key));
            return null;
        }
        return outArray;
    }
}
