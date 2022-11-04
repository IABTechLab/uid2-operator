package com.uid2.operator.service;

import com.uid2.operator.model.AdvertisingToken;
import com.uid2.operator.model.IdentityTokens;
import com.uid2.operator.model.RefreshToken;
import com.uid2.operator.model.UserToken;

import java.time.Instant;

public interface ITokenEncoder {
    IdentityTokens encode(AdvertisingToken advertisingToken, UserToken userToken, RefreshToken refreshToken, Instant refreshFrom, Instant asOf);

    AdvertisingToken decodeAdvertisingToken(String base64String);

    RefreshToken decodeRefreshToken(String base64String);
}
