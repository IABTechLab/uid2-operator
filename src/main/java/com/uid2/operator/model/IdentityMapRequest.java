package com.uid2.operator.model;

import com.fasterxml.jackson.annotation.*;
import java.util.List;

public record IdentityMapRequest (
        @JsonProperty("email") @JsonSetter(contentNulls = Nulls.FAIL) List<IdentityInput> email,
        @JsonProperty("email_hash") @JsonSetter(contentNulls = Nulls.FAIL) List<IdentityInput> email_hash,
        @JsonProperty("phone") @JsonSetter(contentNulls = Nulls.FAIL) List<IdentityInput> phone,
        @JsonProperty("phone_hash") @JsonSetter(contentNulls = Nulls.FAIL) List<IdentityInput> phone_hash
){
    public record IdentityInput(
        @JsonProperty("i") @JsonSetter(nulls = Nulls.FAIL) String input
    ) {}
}
