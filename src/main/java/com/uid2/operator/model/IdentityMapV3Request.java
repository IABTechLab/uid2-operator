package com.uid2.operator.model;

import com.fasterxml.jackson.annotation.*;

public record IdentityMapV3Request(
        @JsonSetter(contentNulls = Nulls.FAIL)
        @JsonProperty("email") IdentityInput[] email,

        @JsonSetter(contentNulls = Nulls.FAIL)
        @JsonProperty("email_hash") IdentityInput[] email_hash,

        @JsonSetter(contentNulls = Nulls.FAIL)
        @JsonProperty("phone") IdentityInput[] phone,

        @JsonSetter(contentNulls = Nulls.FAIL)
        @JsonProperty("phone_hash") IdentityInput[] phone_hash
) {
    public record IdentityInput(
            @JsonSetter(nulls = Nulls.FAIL)
            @JsonProperty("i") String input
    ) {}
}
