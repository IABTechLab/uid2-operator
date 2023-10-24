package com.uid2.operator.operatorkey;

import com.uid2.operator.Const;
import io.vertx.core.json.JsonObject;

public class ConfigOperatorKeyRetriever implements IOperatorKeyRetriever {
    private final JsonObject config;

    public ConfigOperatorKeyRetriever(JsonObject config) {
        this.config = config;
    }

    @Override
    public String retrieve() {
        return this.config.getString(Const.Config.CoreApiTokenProp);
    }
}
