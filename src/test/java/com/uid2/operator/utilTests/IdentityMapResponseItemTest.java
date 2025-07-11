package com.uid2.operator.utilTests;

import com.uid2.operator.model.IdentityMapResponseItem;
import com.uid2.operator.service.EncodingUtils;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;

import static org.junit.Assert.*;


public class IdentityMapResponseItemTest {
    @Test
    public void doRawUidResponseTest() throws NoSuchAlgorithmException {
        assertEquals(IdentityMapResponseItem.OptoutIdentity.bucketId, "");
        assertTrue(IdentityMapResponseItem.OptoutIdentity.isOptedOut());

        IdentityMapResponseItem optoutResponse = new IdentityMapResponseItem(new byte[33], null, null, null);
        assertTrue(optoutResponse.isOptedOut());

        byte[] rawUid = new byte[33];
        for(int i = 0; i < 33; i++) {
            rawUid[i] = (byte) i;
        }

        final Long expectedRefreshFrom = EncodingUtils.NowUTCMillis().toEpochMilli();
        byte[] expectedPreviousRawUid = new byte[33];
        for(int i = 0; i < 33; i++) {
            rawUid[i] = (byte) 88;
        }

        IdentityMapResponseItem generatedUid = new IdentityMapResponseItem(rawUid, "12345", expectedPreviousRawUid, expectedRefreshFrom);
        assertFalse(generatedUid.isOptedOut());
        assertTrue(Arrays.equals(rawUid, generatedUid.rawUid));
        assertArrayEquals(expectedPreviousRawUid, generatedUid.previousRawUid);
        assertEquals(expectedRefreshFrom, generatedUid.refreshFrom);
    }
}
