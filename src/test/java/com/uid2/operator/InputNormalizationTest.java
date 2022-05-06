// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package com.uid2.operator;

import com.uid2.operator.service.EncodingUtils;
import com.uid2.operator.service.InputUtil;
import junit.framework.TestCase;
import org.junit.Assert;

import java.util.Random;

public class InputNormalizationTest extends TestCase {

    public void testInvalidEmailNormalization() {
        final String[] invalidTEstCases = new String[]{
            "",
            " @",
            "@",
            "a@",
            "@b",
            "@b.com",
            "+",
            " ",
            "+@gmail.com",
            ".+@gmail.com",
            "a@ba@z.com"
        };

        for (String s : invalidTEstCases) {
            System.out.println("Negative case " + s);
            final InputUtil.InputVal normalized = InputUtil.NormalizeEmail(s);
            Assert.assertEquals(normalized.getProvided(), s);
            Assert.assertFalse(normalized.isValid());

        }

    }

    public void testValidEmailNormalization() {
        final String[][] validTestCases = new String[][]{
            new String[]{"TEst.TEST@Test.com ", "test.test@test.com", "dvECjPKZHya0/SIhSGwP0m8SgTv1vzLxPULUOsm880M="},
            new String[]{"test.test@test.com", "test.test@test.com", "dvECjPKZHya0/SIhSGwP0m8SgTv1vzLxPULUOsm880M="},
            new String[]{"test.test@gmail.com", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="},
            new String[]{"test+test@test.com", "test+test@test.com", "rQ4yzdOz4uG8N54326QyZD6/JwqrXn4lmy34cVCojB8="},
            new String[]{"+test@test.com", "+test@test.com", "weFizOVVWKlLfyorbBU8oxYDv4HJtTZCPMyZ4THzUQE="},
            new String[]{"test+test@gmail.com", "test@gmail.com", "h5JGBrQTGorO7q6IaFMfu5cSqqB6XTp1aybOD11spnQ="},
            new String[]{"testtest@test.com", "testtest@test.com", "d1Lr/s4GLLX3SvQVMoQdIMfbQPMAGZYry+2V+0pZlQg="},
            new String[]{" testtest@test.com", "testtest@test.com", "d1Lr/s4GLLX3SvQVMoQdIMfbQPMAGZYry+2V+0pZlQg="},
            new String[]{"testtest@test.com ", "testtest@test.com", "d1Lr/s4GLLX3SvQVMoQdIMfbQPMAGZYry+2V+0pZlQg="},
            new String[]{" testtest@test.com ", "testtest@test.com", "d1Lr/s4GLLX3SvQVMoQdIMfbQPMAGZYry+2V+0pZlQg="},
            new String[]{"  testtest@test.com  ", "testtest@test.com", "d1Lr/s4GLLX3SvQVMoQdIMfbQPMAGZYry+2V+0pZlQg="},
            new String[]{" test.test@gmail.com", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="},
            new String[]{"test.test@gmail.com ", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="},
            new String[]{" test.test@gmail.com ", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="},
            new String[]{"  test.test@gmail.com  ", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="},
            new String[]{"TEstTEst@gmail.com  ", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="},
            new String[]{"TEstTEst@GMail.Com  ", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="},
            new String[]{" TEstTEst@GMail.Com  ", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="},
            new String[]{"TEstTEst@GMail.Com", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="},
            new String[]{"TEst.TEst@GMail.Com", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="},
            new String[]{"TEst.TEst+123@GMail.Com", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="},
            new String[]{"TEst.TEST@Test.com ", "test.test@test.com", "dvECjPKZHya0/SIhSGwP0m8SgTv1vzLxPULUOsm880M="},
            new String[]{"TEst.TEST@Test.com ", "test.test@test.com", "dvECjPKZHya0/SIhSGwP0m8SgTv1vzLxPULUOsm880M="},
            new String[]{"\uD83D\uDE0Atesttest@test.com", "\uD83D\uDE0Atesttest@test.com", "fAFEUqApQ0V/M9mLj/IO54CgKgtQuARKsOMqtFklD4k="},
            new String[]{"testtest@\uD83D\uDE0Atest.com", "testtest@\uD83D\uDE0Atest.com", "tcng5pttf7Y2z4ylZTROvIMw1+IVrMpR4D1KeXSrdiM="},
            new String[]{"testtest@test.com\uD83D\uDE0A", "testtest@test.com\uD83D\uDE0A", "0qI21FPLkuez/8RswfmircHPYz9Dtf7/Nch1rSWEQf0="},

        };

        for (String[] testCase : validTestCases) {
            System.out.println("Positive Test case " + testCase[0] + " Expected : " + testCase[1]);
            final InputUtil.InputVal normalization = InputUtil.NormalizeEmail(testCase[0]);
            Assert.assertEquals(normalization.getProvided(), testCase[0]);
            Assert.assertTrue(normalization.isValid());
            Assert.assertEquals(testCase[1], normalization.getNormalized());
            Assert.assertEquals(testCase[2], EncodingUtils.toBase64String(normalization.getIdentityInput()));
        }
    }

    public void testValidHashNormalization() {
        // These hashes are SHA256 of foo@bar.com
        final String masterHash = "DH5qQFhi5ALrdqcPiib8cy0Hwykx6frpqxWCkR0uijs=";

        final String[] testCases = new String[]{
            masterHash,
            "0C7E6A405862E402EB76A70F8A26FC732D07C32931E9FAE9AB1582911D2E8A3B",
            "0c7e6a405862e402eb76a70f8a26fc732d07c32931e9fae9ab1582911d2e8a3b",
        };
        for (final String s : testCases) {
            System.out.println("Testing hash " + s);
            final InputUtil.InputVal normalization = InputUtil.NormalizeHash(s);
            Assert.assertEquals(s, normalization.getProvided());
            Assert.assertTrue(normalization.isValid());
            Assert.assertEquals(masterHash, normalization.getNormalized());
            Assert.assertEquals(masterHash, EncodingUtils.toBase64String(normalization.getIdentityInput()));
        }
    }

    public void testInvalidHashNormalization() {
        final String[] testCases = new String[]{
            "",
            "asdaksjdakfj",
            "DH5qQFhi5ALrdqcPiib8cy0Hwykx6frpqxWCkR0uijs",
            "QFhi5ALrdqcPiib8cy0Hwykx6frpqxWCkR0uijs",
            "0Z7E6A405862E402EB76A70F8A26FC732D07C32931E9FAE9AB1582911D2E8A3B",
            "0C7E6A405862E402EB76A70F8A26FC732D07C32931E9FAE9AB1582911D2E8A3B00",
            "000C7E6A405862E402EB76A70F8A26FC732D07C32931E9FAE9AB1582911D2E8A3B",
        };

        for (final String s : testCases) {
            System.out.println("Testing Invalid hash " + s);
            final InputUtil.InputVal normalization = InputUtil.NormalizeHash(s);
            Assert.assertEquals(normalization.getProvided(), s);
            Assert.assertFalse(normalization.isValid());
        }

    }

    public void testHexStringParsing() {
        String s0 = "06a418f467a14e1631a317b107548a1039d26f12ea45301ab14e7684b36ede58";
        String s1 = "f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";

        Assert.assertEquals(s0, bytesToHex(EncodingUtils.fromHexString(s0)));
        Assert.assertEquals(s1, bytesToHex(EncodingUtils.fromHexString(s1)));

        Random r = new Random();
        for(int i = 0; i < 100; i++) {
            int len = (r.nextInt(50) + 16) * 2;
            StringBuilder sb = new StringBuilder();
            for(int j = 0; j < len; j++)
                sb.append(HEX_ARRAY[r.nextInt(HEX_ARRAY.length)]);
            String s = sb.toString();
            Assert.assertEquals(s, bytesToHex(EncodingUtils.fromHexString(s)));
        }
    }

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
    private static String bytesToHex(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
