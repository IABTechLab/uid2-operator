package com.uid2.operator;

import com.uid2.shared.model.TokenVersion;

public class EUIDOperatorVerticleTestV4 extends EUIDOperatorVerticleTest {
    @Override
    protected TokenVersion getTokenVersion() {
        return TokenVersion.V4;
    }
}
