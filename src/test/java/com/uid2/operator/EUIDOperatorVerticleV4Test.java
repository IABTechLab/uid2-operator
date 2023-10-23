package com.uid2.operator;

import com.uid2.shared.model.TokenVersion;

import java.io.IOException;

public class EUIDOperatorVerticleV4Test extends EUIDOperatorVerticleTest {
    public EUIDOperatorVerticleV4Test() throws IOException {
    }

    @Override
    protected TokenVersion getTokenVersion() {
        return TokenVersion.V4;
    }
}
