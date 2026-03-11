package com.uid2.operator.model;

import com.uid2.operator.service.InputUtil;

import java.util.Objects;

public record IdentityMapV2Input(String diiType, InputUtil.InputVal[] inputList) {
    public IdentityMapV2Input {
        Objects.requireNonNull(diiType);
        Objects.requireNonNull(inputList);
    }
}
