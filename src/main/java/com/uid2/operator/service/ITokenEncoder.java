package com.uid2.operator.service;

import com.uid2.operator.model.AdvertisingTokenInput;
import com.uid2.operator.model.Identity;
import com.uid2.operator.model.RefreshTokenInput;

import java.time.Instant;

public interface ITokenEncoder {
    Identity encode(AdvertisingTokenInput advertisingTokenInput, RefreshTokenInput refreshTokenInput, Instant refreshFrom, Instant asOf);

    AdvertisingTokenInput decodeAdvertisingToken(String base64String);

    RefreshTokenInput decodeRefreshToken(String base64String);
}
