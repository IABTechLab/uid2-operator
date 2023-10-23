package com.uid2.operator;

import com.uid2.shared.model.TokenVersion;

import java.io.IOException;

public class UidOperatorVerticleV4Test extends UIDOperatorVerticleTest {
    public UidOperatorVerticleV4Test() throws IOException {
    }

    @Override
    protected TokenVersion getTokenVersion() {return TokenVersion.V4;}

}
