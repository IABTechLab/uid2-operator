package com.uid2.operator.model;

import com.fasterxml.jackson.annotation.*;

public record IdentityMapV3Request(
        @JsonSetter(contentNulls = Nulls.FAIL)
        @JsonProperty("email") String[] email,

        @JsonSetter(contentNulls = Nulls.FAIL)
        @JsonProperty("email_hash") String[] email_hash,

        @JsonSetter(contentNulls = Nulls.FAIL)
        @JsonProperty("phone") String[] phone,

        @JsonSetter(contentNulls = Nulls.FAIL)
        @JsonProperty("phone_hash") String[] phone_hash
) {
}
