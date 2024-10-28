package com.uid2.operator;

import com.uid2.operator.service.EncodingUtils;
import com.uid2.operator.util.PrivacyBits;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.reader.RotatingClientKeyProvider;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.json.JsonObject;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.junit.Assert.*;


public class PrivacyBitsTest {
    @Test
    public void generateNewClientKeys() throws NoSuchAlgorithmException {
        assertEquals(PrivacyBits.DEFAULT.getAsInt(), 1);
        PrivacyBits pb1 = new PrivacyBits();
        assertEquals(pb1.getAsInt(), 0);
        assertEquals(pb1.hashCode(), 0);
        assertNotEquals(pb1, PrivacyBits.fromInt(1));
        assertNotEquals(pb1, PrivacyBits.fromInt(121));
        assertFalse(pb1.isClientSideTokenGenerated());
        assertFalse(pb1.isClientSideTokenOptedOut());

        pb1.setLegacyBit();
        assertEquals(pb1.getAsInt(), 0b1);
        assertEquals(pb1.hashCode(), 0b1);
        assertEquals(pb1, PrivacyBits.fromInt(1));
        assertNotEquals(pb1, PrivacyBits.fromInt(121));
        assertFalse(pb1.isClientSideTokenGenerated());
        assertFalse(pb1.isClientSideTokenOptedOut());


        pb1.setClientSideTokenGenerate();
        assertEquals(pb1.getAsInt(), 0b11);
        assertEquals(pb1.hashCode(), 0b11);
        assertEquals(pb1, PrivacyBits.fromInt(3));
        assertNotEquals(pb1, PrivacyBits.fromInt(121));
        assertTrue(pb1.isClientSideTokenGenerated());
        assertFalse(pb1.isClientSideTokenOptedOut());


        pb1.setClientSideTokenGenerateOptout();
        assertEquals(pb1.getAsInt(), 0b111);
        assertEquals(pb1.hashCode(), 0b111);
        assertEquals(pb1, PrivacyBits.fromInt(7));
        assertNotEquals(pb1, PrivacyBits.fromInt(121));
        assertTrue(pb1.isClientSideTokenGenerated());
        assertTrue(pb1.isClientSideTokenOptedOut());

        PrivacyBits pb2 = new PrivacyBits(pb1);
        assertEquals(pb2.getAsInt(), 0b111);

        PrivacyBits pb3 = PrivacyBits.fromInt(0b10110);
        assertEquals(pb3.getAsInt(), 0b10110);
        pb3.setLegacyBit();
        assertEquals(pb3.getAsInt(), 0b10111);
    }
}
