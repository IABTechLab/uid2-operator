package com.uid2.operator.service;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

public class EncodingUtils {

    public static String toBase64String(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    public static byte[] toBase64(byte[] b) {
        return Base64.getEncoder().encode(b);
    }

    public static byte[] fromBase64(String s) { return Base64.getDecoder().decode(s); }

    public static byte[] fromBase64(byte[] b) { return Base64.getDecoder().decode(b); }

    public static String getSha256(String input, String salt) {
        return toBase64String(getSha256Bytes(input, salt));
    }

    public static String getSha256(String input) {
        return toBase64String(getSha256Bytes(input));
    }

    public static byte[] getSha256Bytes(String input) {
        return getSha256Bytes(input, null);
    }

    public static byte[] getSha256Bytes(String input, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(input.getBytes());
            if (salt != null) {
                md.update(salt.getBytes());
            }
            return md.digest();
        } catch (Exception e) {
            throw new RuntimeException("Trouble Generating SHA256", e);
        }
    }

    public static String generateIdGuid(String value) {
        byte[] b = value.getBytes(Charset.forName("UTF8"));
        long high = 0L;
        high = high | (long) b[0] << (7 * 8);
        high = high | (long) b[1] << (6 * 8);
        high = high | (long) b[2] << (5 * 8);
        high = high | (long) b[3] << (5 * 8);
        high = high | (long) b[4] << (3 * 8);
        high = high | (long) b[5] << (2 * 8);
        high = high | (long) b[6] << (1 * 8);
        high = high | (long) b[7];

        long low = 0;
        low = low | (long) b[8] << (7 * 8);
        low = low | (long) b[9] << (6 * 8);
        low = low | (long) b[10] << (5 * 8);
        low = low | (long) b[11] << (4 * 8);
        low = low | (long) b[12] << (3 * 8);
        low = low | (long) b[13] << (2 * 8);
        low = low | (long) b[14] << (1 * 8);
        low = low | (long) b[15];

        String uid = new UUID(high, low).toString();

        return uid;

    }

    public static Instant NowUTCMillis() {
        return Instant.now().truncatedTo(ChronoUnit.MILLIS);
    }

    public static Instant NowUTCMillis(Clock clock) {
        return Instant.now(clock).truncatedTo(ChronoUnit.MILLIS);
    }

    public static byte[] fromHexString(String hs) throws NumberFormatException {
        if(hs.length() % 2 == 1) {
            throw new NumberFormatException("input " + hs.substring(0, 5) + "... is not a valid hex string - odd length");
        }

        byte[] s = new byte[hs.length() / 2];
        for(int i = 0; i < hs.length(); i++) {
            int v; char c = hs.charAt(i);
            if(c >= '0' && c <= '9') v = c - '0';
            else if(c >= 'A' && c <= 'F') v = c - 'A' + 10;
            else if(c >= 'a' && c <= 'f') v = c - 'a' + 10;
            else throw new NumberFormatException("input " + hs.substring(0, 5) + "... is not a valid hex string - invalid character");
            if (i % 2 == 0) {
                s[i / 2] = (byte) (s[i / 2] | (byte)((v << 4) & 0xFF));
            } else {
                s[i / 2] = (byte) (s[i / 2] | (byte)(v & 0xFF));
            }
        }

        return s;
    }
}
