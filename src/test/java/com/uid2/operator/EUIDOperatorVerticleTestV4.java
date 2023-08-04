package com.uid2.operator;

import com.uid2.shared.model.TokenVersion;

import java.io.IOException;

public class EUIDOperatorVerticleTestV4 extends EUIDOperatorVerticleTest {
    public EUIDOperatorVerticleTestV4() throws IOException {
    }

    @Override
    protected TokenVersion getTokenVersion() {
        return TokenVersion.V4;
    }
}
