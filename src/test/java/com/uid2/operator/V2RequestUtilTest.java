package com.uid2.operator;

import com.uid2.operator.service.V2RequestUtil;
import org.junit.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class V2RequestUtilTest {
    @Test
    public void testParseRequestWithNullBody() {
        V2RequestUtil.V2Request res = V2RequestUtil.parseRequest(null, null);
        assertEquals("Invalid body: Body is missing.", res.errorMessage);
    }

    @Test
    public void testParseRequestWithNonBase64Body() {
        V2RequestUtil.V2Request res = V2RequestUtil.parseRequest("test string", null);
        assertEquals("Invalid body: Body is not valid base64.", res.errorMessage);
    }

    @Test
    public void testParseRequestWithTooShortBody() {
        V2RequestUtil.V2Request res = V2RequestUtil.parseRequest("dGVzdA==", null);
        assertEquals("Invalid body: Body too short. Check encryption method.", res.errorMessage);
    }
}
