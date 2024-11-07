package com.uid2.operator.utilTests;

import com.uid2.operator.model.RawUidResponse;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.Assert.*;


public class RawUidResponseTest {
    @Test
    public void doRawUidResponseTest() throws NoSuchAlgorithmException {
        assertEquals(RawUidResponse.OptoutIdentity.bucketId, "");
        assertTrue(RawUidResponse.OptoutIdentity.isOptedOut());

        RawUidResponse optoutResponse = new RawUidResponse(new byte[33], null);
        assertTrue(optoutResponse.isOptedOut());

        byte[] rawUid = new byte[33];
        for(int i = 0; i < 33; i++) {
            rawUid[i] = (byte) i;
        }

        RawUidResponse generatedUid = new RawUidResponse(rawUid, "12345");
        assertFalse(generatedUid.isOptedOut());
        assertTrue(Arrays.equals(rawUid, generatedUid.rawUid));
    }
}
