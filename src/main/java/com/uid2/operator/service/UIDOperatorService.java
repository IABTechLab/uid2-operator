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

package com.uid2.operator.service;

import com.uid2.operator.model.*;
import com.uid2.shared.model.SaltEntry;
import com.uid2.shared.store.IKeyStore;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.shared.store.ISaltProvider;
import com.uid2.shared.model.EncryptionKey;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class UIDOperatorService implements IUIDOperatorService {

    private static int CURRENT_TOKEN_VERSION = 2;
    private static int DEFAULT_EXPIRY_MILLIS = 4 * 60 * 60 * 1000; // 4 hours
    public static long DEFAULT_VALID_MILLIS = Duration.ofDays(30).toMillis();

    private static Instant RefreshCutoff = LocalDateTime.parse("2021-03-08T17:00:00", DateTimeFormatter.ISO_LOCAL_DATE_TIME).toInstant(ZoneOffset.UTC);
    private final IKeyStore keyStore;
    private final ISaltProvider saltProvider;
    private final IOptOutStore optOutStore;
    private final ITokenEncoder encoder;
    private final Clock clock;
    private Map<String, VerificationEntry> verificationCodes = new HashMap<String, VerificationEntry>();
    private final String testOptOutKey;

    public UIDOperatorService(IKeyStore keyStore, IOptOutStore optOutStore, ISaltProvider saltProvider, ITokenEncoder encoder, Clock clock) {
        this.keyStore = keyStore;
        this.saltProvider = saltProvider;
        this.encoder = encoder;
        this.optOutStore = optOutStore;
        this.clock = clock;

        // initialize test optout key
        testOptOutKey = getFirstLevelKey(InputUtil.NormalizeEmail("optout@email.com").getIdentityInput(), Instant.now());
    }

    private static int getRandomVerificationNumber() {
        return (int) ((Math.random() * (9999 - 1000)) + 1000);
    }

    @Override
    public List<EncryptionKey> getConsortiumKeys() {
        return this.keyStore.getSnapshot().getActiveKeySet();
    }

    @Override
    public IdentityTokens generateIdentity(IdentityRequest request) {
        final Instant now = EncodingUtils.NowUTCMillis();
        final String firstLevelKey = getFirstLevelKey(request.getEmailSha(), now);
        return generateIdentity(firstLevelKey, request.getSiteId(), request.getPrivacyBits(), now);
    }

    @Override
    public void generateIdentityAsync(IdentityRequest request, Handler<AsyncResult<IdentityTokens>> handler) {

    }

    @Override
    public void refreshIdentityAsync(String refreshToken, Handler<AsyncResult<RefreshResponse>> handler) {

        final RefreshToken token;
        try {
            token = this.encoder.decode(refreshToken);
        } catch (Throwable t) {
            handler.handle(Future.succeededFuture(RefreshResponse.Invalid));
            return;
        }
        if (token == null) {
            handler.handle(Future.succeededFuture(RefreshResponse.Invalid));
            return;
        }

        if (token.getIdentity().getEstablished().isBefore(RefreshCutoff)) {
            handler.handle(Future.succeededFuture(RefreshResponse.Deprecated));
            return;
        }

        if (token.getValidTill().isBefore(Instant.now(this.clock))) {
            handler.handle(Future.succeededFuture(RefreshResponse.Expired));
            return;
        }

        if (testOptOutKey.equals(token.getIdentity().getId())) {
            handler.handle(Future.succeededFuture(RefreshResponse.Optout));
            return;
        }

        this.optOutStore.getLatestEntry(token.getIdentity().getId(), r -> {
            if (r.succeeded()) {
                final Instant logoutEntry = r.result();
                final RefreshResponse response;

                if (logoutEntry == null || token.getCreatedAt().isAfter(logoutEntry)) {
                    response = RefreshResponse.Refreshed(this.generateIdentity(
                            token.getIdentity().getId(), token.getIdentity().getSiteId(),
                            token.getIdentity().getPrivacyBits(), token.getIdentity().getEstablished()));
                } else {
                    response = RefreshResponse.Optout;
                }
                handler.handle(Future.succeededFuture(response));
            } else {
                handler.handle(Future.succeededFuture(RefreshResponse.Invalid));
            }
        });

    }

    @Override
    public MappedIdentity map(String input, Instant asOf) {
        final String firstLevelKey = getFirstLevelKey(input, asOf);
        return getAdvertisementId(firstLevelKey, asOf);
    }

    public List<SaltEntry> getModifiedBuckets(Instant sinceTimestamp) {
        return this.saltProvider.getSnapshot(Instant.now()).getModifiedSince(sinceTimestamp);
    }

    @Override
    public void InvalidateTokensAsync(String inputIdentity, Handler<AsyncResult<Instant>> handler) {
        final Instant now = Instant.now();
        final String firstLevelKey = this.getFirstLevelKey(inputIdentity, now);
        final MappedIdentity mappedIdentity = getAdvertisementId(firstLevelKey, now);

        this.optOutStore.addEntry(firstLevelKey, mappedIdentity.getAdvertisingId(), r -> {
            if (r.succeeded()) {
                handler.handle(Future.succeededFuture(r.result()));
            } else {
                handler.handle(Future.failedFuture(r.cause()));
            }
        });
    }

    @Override
    public boolean doesMatch(String advertisingToken, String inputIdentity, Instant asOf) {
        final String firstLevelHash = getFirstLevelKey(inputIdentity, asOf);
        final MappedIdentity identity = getAdvertisementId(firstLevelHash, asOf);

        final AdvertisingToken token = this.encoder.decodeAdvertisingToken(advertisingToken);
        return token.getIdentity().getId().equals(identity.getAdvertisingId());

    }

    private String getFirstLevelKey(String emailAddress, Instant asOf) {
        return TokenUtils.getFirstLevelKey(emailAddress, this.saltProvider.getSnapshot(asOf).getFirstLevelSalt());
    }

    private MappedIdentity getAdvertisementId(String firstLevelKey, Instant asOf) {
        final SaltEntry rotatingSalt = this.saltProvider.getSnapshot(asOf).getRotatingSalt(firstLevelKey);

        return new MappedIdentity(TokenUtils.getAdvertisingId(firstLevelKey, rotatingSalt.getSalt()), rotatingSalt.getHashedId());
    }

    private IdentityTokens generateIdentity(String firstLevelKey, int siteId, int privicyBits, Instant established) {
        final Instant nowUtc = EncodingUtils.NowUTCMillis();

        final MappedIdentity mappedIdentity = getAdvertisementId(firstLevelKey, nowUtc);

        final UserIdentity refreshIdentity = new UserIdentity(firstLevelKey, siteId, privicyBits, established);
        final UserIdentity advertisementIdentity = new UserIdentity(mappedIdentity.getAdvertisingId(), siteId, privicyBits, established);

        return this.encoder.encode(
            this.createAdvertisementToken(advertisementIdentity, nowUtc),
            this.createUserToken(advertisementIdentity, nowUtc),
            this.createRefreshToken(refreshIdentity, nowUtc)
        );
    }

    private RefreshToken createRefreshToken(UserIdentity userIdentity, Instant now) {
        return new RefreshToken(CURRENT_TOKEN_VERSION,
            now,
            now.plusMillis(DEFAULT_EXPIRY_MILLIS),
            now.plusMillis(DEFAULT_VALID_MILLIS), userIdentity);
    }

    private AdvertisingToken createAdvertisementToken(UserIdentity userIdentity, Instant now) {
        return new AdvertisingToken(CURRENT_TOKEN_VERSION, now, now.plusMillis(DEFAULT_EXPIRY_MILLIS), userIdentity);
    }

    private UserToken createUserToken(UserIdentity userIdentity, Instant now) {
        return new UserToken(CURRENT_TOKEN_VERSION, now, now.plusMillis(DEFAULT_EXPIRY_MILLIS), userIdentity, 2);
    }

    private static class VerificationEntry {
        private String token;
        private int code;

        public VerificationEntry(String token, int code) {
            this.token = token;
            this.code = code;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            VerificationEntry that = (VerificationEntry) o;
            return code == that.code &&
                Objects.equals(token, that.token);
        }

        @Override
        public int hashCode() {
            return Objects.hash(token, code);
        }
    }

}
