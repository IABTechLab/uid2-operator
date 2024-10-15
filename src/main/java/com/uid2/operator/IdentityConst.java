package com.uid2.operator;

import com.uid2.operator.service.EncodingUtils;

public class IdentityConst {
    // DIIs for generating optout tokens for legacy participants - to be deprecated
    public static final String OptOutTokenIdentityForEmail = "optout@unifiedid.com";
    public static final String OptOutTokenIdentityForPhone = "+00000000001";

    // DIIs for for testing with token/validate endpoint, see https://unifiedid.com/docs/endpoints/post-token-validate
    public static final String ValidateIdentityForEmail = "validate@example.com";
    public static final String ValidateIdentityForPhone = "+12345678901";
    public static final byte[] ValidateIdentityForEmailHash = EncodingUtils.getSha256Bytes(IdentityConst.ValidateIdentityForEmail);
    public static final byte[] ValidateIdentityForPhoneHash = EncodingUtils.getSha256Bytes(IdentityConst.ValidateIdentityForPhone);

    // DIIs to use when you want to generate a optout response in token generation or identity map
    public static final String OptOutIdentityForEmail = "optout@example.com";
    public static final String OptOutIdentityForPhone = "+00000000000";

    // DIIs to use when you want to generate a UID token but when doing refresh token, you want to always get an optout response
    // to test the optout handling workflow
    public static final String RefreshOptOutIdentityForEmail = "refresh-optout@example.com";
    public static final String RefreshOptOutIdentityForPhone = "+00000000002";
}
