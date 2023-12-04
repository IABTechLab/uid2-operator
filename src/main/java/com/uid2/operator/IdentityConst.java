package com.uid2.operator;

import com.uid2.operator.service.EncodingUtils;

public class IdentityConst {

    public static final String OptOutTokenIdentityForEmail = "optout@unifiedid.com";
    public static final String OptOutTokenIdentityForPhone = "+00000000001";
    public static final String ValidateIdentityForEmail = "validate@example.com";
    public static final String ValidateIdentityForPhone = "+12345678901";
    public static final byte[] ValidateIdentityForEmailHash = EncodingUtils.getSha256Bytes(IdentityConst.ValidateIdentityForEmail);
    public static final byte[] ValidateIdentityForPhoneHash = EncodingUtils.getSha256Bytes(IdentityConst.ValidateIdentityForPhone);
    public static final String OptOutIdentityForEmail = "optout@example.com";
    public static final String OptOutIdentityForPhone = "+00000000000";
    public static final String RefreshOptOutIdentityForEmail = "refresh-optout@example.com";
    public static final String RefreshOptOutIdentityForPhone = "+00000000002";



}
