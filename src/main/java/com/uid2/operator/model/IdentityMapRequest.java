package com.uid2.operator.model;

import com.fasterxml.jackson.annotation.*;
import java.util.List;

public record IdentityMapRequest (
        @JsonSetter(contentNulls = Nulls.FAIL)
        @JsonProperty("email") List<IdentityInput>email,

        @JsonSetter(contentNulls = Nulls.FAIL)
        @JsonProperty("email_hash")  List<IdentityInput> email_hash,

        @JsonSetter(contentNulls = Nulls.FAIL)
        @JsonProperty("phone") List<IdentityInput> phone,

        @JsonSetter(contentNulls = Nulls.FAIL)
        @JsonProperty("phone_hash") List<IdentityInput> phone_hash
){
    public record IdentityInput(
            @JsonSetter(nulls = Nulls.FAIL)
            @JsonProperty("i") String input
    ) {}
}
