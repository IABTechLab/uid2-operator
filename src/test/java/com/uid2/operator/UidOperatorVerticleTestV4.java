package com.uid2.operator;

import com.uid2.shared.model.TokenVersion;

import java.io.IOException;

public class UidOperatorVerticleTestV4 extends UIDOperatorVerticleTest {
    public UidOperatorVerticleTestV4() throws IOException {
    }

    @Override
    protected TokenVersion getTokenVersion() {return TokenVersion.V4;}

}
