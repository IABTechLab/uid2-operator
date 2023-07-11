package com.uid2.operator.service;

import com.uid2.operator.model.AdvertisingToken;
import com.uid2.operator.model.IdentityTokens;
import com.uid2.operator.model.RefreshToken;

import java.time.Instant;

public interface ITokenEncoder {
    IdentityTokens encode(AdvertisingToken advertisingToken, RefreshToken refreshToken, Instant refreshFrom, Instant asOf);

    AdvertisingToken decodeAdvertisingToken(String base64String);

    RefreshToken decodeRefreshToken(String base64String);
}
