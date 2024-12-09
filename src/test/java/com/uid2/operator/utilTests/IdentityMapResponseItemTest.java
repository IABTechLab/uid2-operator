package com.uid2.operator.utilTests;

import com.uid2.operator.model.IdentityMapResponseItem;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.Assert.*;


public class IdentityMapResponseItemTest {
    @Test
    public void doRawUidResponseTest() throws NoSuchAlgorithmException {
        assertEquals(IdentityMapResponseItem.OptoutIdentity.bucketId, "");
        assertTrue(IdentityMapResponseItem.OptoutIdentity.isOptedOut());

        IdentityMapResponseItem optoutResponse = new IdentityMapResponseItem(new byte[33], null);
        assertTrue(optoutResponse.isOptedOut());

        byte[] rawUid = new byte[33];
        for(int i = 0; i < 33; i++) {
            rawUid[i] = (byte) i;
        }

        IdentityMapResponseItem generatedUid = new IdentityMapResponseItem(rawUid, "12345");
        assertFalse(generatedUid.isOptedOut());
        assertTrue(Arrays.equals(rawUid, generatedUid.rawUid));
    }
}
