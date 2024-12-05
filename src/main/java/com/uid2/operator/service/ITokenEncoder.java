package com.uid2.operator.service;

import com.uid2.operator.model.AdvertisingTokenRequest;
import com.uid2.operator.model.IdentityResponse;
import com.uid2.operator.model.TokenRefreshRequest;

import java.time.Instant;

public interface ITokenEncoder {
    IdentityResponse encodeIntoIdentityResponse(AdvertisingTokenRequest advertisingTokenRequest, TokenRefreshRequest tokenRefreshRequest, Instant refreshFrom, Instant asOf);

    AdvertisingTokenRequest decodeAdvertisingToken(String base64String);

    TokenRefreshRequest decodeRefreshToken(String base64String);
}
