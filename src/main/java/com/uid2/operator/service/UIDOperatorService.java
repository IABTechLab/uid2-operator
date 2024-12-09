package com.uid2.operator.service;

import com.uid2.operator.model.*;
import com.uid2.operator.model.identities.FirstLevelHash;
import com.uid2.operator.model.identities.HashedDii;
import com.uid2.operator.model.identities.RawUid;
import com.uid2.operator.util.PrivacyBits;
import com.uid2.shared.model.SaltEntry;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.shared.store.ISaltProvider;
import com.uid2.shared.model.TokenVersion;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static com.uid2.operator.IdentityConst.*;
import static com.uid2.operator.service.TokenUtils.getSiteIdsUsingV4Tokens;

public class UIDOperatorService implements IUIDOperatorService {
    public static final String IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS = "identity_token_expires_after_seconds";
    public static final String REFRESH_TOKEN_EXPIRES_AFTER_SECONDS = "refresh_token_expires_after_seconds";
    public static final String REFRESH_IDENTITY_TOKEN_AFTER_SECONDS = "refresh_identity_token_after_seconds";
    private static final Logger LOGGER = LoggerFactory.getLogger(UIDOperatorService.class);

    private static final Instant RefreshCutoff = LocalDateTime.parse("2021-03-08T17:00:00", DateTimeFormatter.ISO_LOCAL_DATE_TIME).toInstant(ZoneOffset.UTC);
    private final ISaltProvider saltProvider;
    private final IOptOutStore optOutStore;
    private final EncryptedTokenEncoder encoder;
    private final Clock clock;
    private final IdentityScope identityScope;
    private final FirstLevelHash testOptOutIdentityForEmail;
    private final FirstLevelHash testOptOutIdentityForPhone;
    private final FirstLevelHash testValidateIdentityForEmail;
    private final FirstLevelHash testValidateIdentityForPhone;
    private final FirstLevelHash testRefreshOptOutIdentityForEmail;
    private final FirstLevelHash testRefreshOptOutIdentityForPhone;
    private final Duration identityExpiresAfter;
    private final Duration refreshExpiresAfter;
    private final Duration refreshIdentityAfter;

    private final OperatorIdentity operatorIdentity;
    protected final TokenVersion tokenVersionToUseIfNotV4;
    protected final int advertisingTokenV4Percentage;
    protected final Set<Integer> siteIdsUsingV4Tokens;
    private final TokenVersion refreshTokenVersion;
    private final boolean identityV3Enabled;

    private final Handler<Boolean> saltRetrievalResponseHandler;

    public UIDOperatorService(JsonObject config, IOptOutStore optOutStore, ISaltProvider saltProvider, EncryptedTokenEncoder encoder, Clock clock,
                              IdentityScope identityScope, Handler<Boolean> saltRetrievalResponseHandler) {
        this.saltProvider = saltProvider;
        this.encoder = encoder;
        this.optOutStore = optOutStore;
        this.clock = clock;
        this.identityScope = identityScope;
        this.saltRetrievalResponseHandler = saltRetrievalResponseHandler;

        this.testOptOutIdentityForEmail = getFirstLevelHashIdentity(identityScope, IdentityType.Email,
                InputUtil.normalizeEmail(OptOutIdentityForEmail).getIdentityInput(), Instant.now());
        this.testOptOutIdentityForPhone = getFirstLevelHashIdentity(identityScope, IdentityType.Phone,
                InputUtil.normalizePhone(OptOutIdentityForPhone).getIdentityInput(), Instant.now());
        this.testValidateIdentityForEmail = getFirstLevelHashIdentity(identityScope, IdentityType.Email,
                InputUtil.normalizeEmail(ValidateIdentityForEmail).getIdentityInput(), Instant.now());
        this.testValidateIdentityForPhone = getFirstLevelHashIdentity(identityScope, IdentityType.Phone,
                InputUtil.normalizePhone(ValidateIdentityForPhone).getIdentityInput(), Instant.now());
        this.testRefreshOptOutIdentityForEmail = getFirstLevelHashIdentity(identityScope, IdentityType.Email,
                InputUtil.normalizeEmail(RefreshOptOutIdentityForEmail).getIdentityInput(), Instant.now());
        this.testRefreshOptOutIdentityForPhone = getFirstLevelHashIdentity(identityScope, IdentityType.Phone,
                InputUtil.normalizePhone(RefreshOptOutIdentityForPhone).getIdentityInput(), Instant.now());

        this.operatorIdentity = new OperatorIdentity(0, OperatorType.Service, 0, 0);

        this.identityExpiresAfter = Duration.ofSeconds(config.getInteger(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        this.refreshExpiresAfter = Duration.ofSeconds(config.getInteger(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS));
        this.refreshIdentityAfter = Duration.ofSeconds(config.getInteger(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS));

        if (this.identityExpiresAfter.compareTo(this.refreshExpiresAfter) > 0) {
            throw new IllegalStateException(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS + " must be >= " + IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
        }
        if (this.refreshIdentityAfter.compareTo(this.identityExpiresAfter) > 0) {
            throw new IllegalStateException(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS + " must be >= " + REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
        }
        if (this.refreshIdentityAfter.compareTo(this.refreshExpiresAfter) > 0) {
            throw new IllegalStateException(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS + " must be >= " + REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
        }

        this.advertisingTokenV4Percentage = config.getInteger("advertising_token_v4_percentage", 0); //0 indicates token v4 will not be used
        this.siteIdsUsingV4Tokens = getSiteIdsUsingV4Tokens(config.getString("site_ids_using_v4_tokens", ""));
        this.tokenVersionToUseIfNotV4 = config.getBoolean("advertising_token_v3", false) ? TokenVersion.V3 : TokenVersion.V2;

        this.refreshTokenVersion = TokenVersion.V3;
        this.identityV3Enabled = config.getBoolean("identity_v3", false);
    }

    @Override
    public TokenGenerateResponse generateIdentity(TokenGenerateRequest request) {
        final Instant now = EncodingUtils.NowUTCMillis(this.clock);
        final byte[] firstLevelHash = getFirstLevelHash(request.hashedDii.hashedDii(), now);
        final FirstLevelHash firstLevelHashIdentity = new FirstLevelHash(
                request.hashedDii.identityScope(), request.hashedDii.identityType(), firstLevelHash,
                request.establishedAt);

        if (request.shouldCheckOptOut() && getGlobalOptOutResult(firstLevelHashIdentity, false).isOptedOut()) {
            return TokenGenerateResponse.OptOutResponse;
        } else {
            return generateIdentity(request.sourcePublisher, firstLevelHashIdentity, request.privacyBits);
        }
    }

    @Override
    public TokenRefreshResponse refreshIdentity(TokenRefreshRequest input) {
        // should not be possible as different scopes should be using different keys, but just in case
        if (input.firstLevelHash.identityScope() != this.identityScope) {
            return TokenRefreshResponse.Invalid;
        }

        if (input.firstLevelHash.establishedAt().isBefore(RefreshCutoff)) {
            return TokenRefreshResponse.Deprecated;
        }

        final Instant now = clock.instant();

        if (input.expiresAt.isBefore(now)) {
            return TokenRefreshResponse.Expired;
        }

        final boolean isCstg = input.privacyBits.isClientSideTokenGenerated();

        try {
            final GlobalOptoutResult logoutEntry = getGlobalOptOutResult(input.firstLevelHash, true);
            final boolean optedOut = logoutEntry.isOptedOut();

            final Duration durationSinceLastRefresh = Duration.between(input.createdAt, now);

            if (!optedOut) {
                TokenGenerateResponse tokenGenerateResponse = this.generateIdentity(input.sourcePublisher,
                        input.firstLevelHash,
                        input.privacyBits);

                return TokenRefreshResponse.createRefreshedResponse(tokenGenerateResponse, durationSinceLastRefresh, isCstg);
            } else {
                return TokenRefreshResponse.Optout;
            }
        } catch (KeyManager.NoActiveKeyException e) {
            return TokenRefreshResponse.NoActiveKey;
        } catch (Exception ex) {
            return TokenRefreshResponse.Invalid;
        }
    }

    @Override
    public IdentityMapResponseItem mapHashedDii(IdentityMapRequestItem request) {
        final FirstLevelHash firstLevelHash = getFirstLevelHashIdentity(request.hashedDii,
                request.asOf);
        if (request.shouldCheckOptOut() && getGlobalOptOutResult(firstLevelHash, false).isOptedOut()) {
            return IdentityMapResponseItem.OptoutIdentity;
        } else {
            return generateRawUid(firstLevelHash, request.asOf);
        }
    }

    @Override
    public IdentityMapResponseItem map(HashedDii diiIdentity, Instant asOf) {
        final FirstLevelHash firstLevelHash = getFirstLevelHashIdentity(diiIdentity, asOf);
        return generateRawUid(firstLevelHash, asOf);
    }

    @Override
    public List<SaltEntry> getModifiedBuckets(Instant sinceTimestamp) {
        return getSaltProviderSnapshot(Instant.now()).getModifiedSince(sinceTimestamp);
    }

    private ISaltProvider.ISaltSnapshot getSaltProviderSnapshot(Instant asOf) {
        ISaltProvider.ISaltSnapshot snapshot = this.saltProvider.getSnapshot(asOf);
        if(snapshot.getExpires().isBefore(Instant.now())) {
            saltRetrievalResponseHandler.handle(true);
        } else {
            saltRetrievalResponseHandler.handle(false);
        }
        return snapshot;
    }

    @Override
    public void invalidateTokensAsync(HashedDii diiIdentity, Instant asOf, Handler<AsyncResult<Instant>> handler) {
        final FirstLevelHash firstLevelHash = getFirstLevelHashIdentity(diiIdentity, asOf);
        final IdentityMapResponseItem identityMapResponseItem = generateRawUid(firstLevelHash, asOf);

        this.optOutStore.addEntry(firstLevelHash, identityMapResponseItem.rawUid, r -> {
            if (r.succeeded()) {
                handler.handle(Future.succeededFuture(r.result()));
            } else {
                handler.handle(Future.failedFuture(r.cause()));
            }
        });
    }

    @Override
    public boolean advertisingTokenMatches(String advertisingToken, HashedDii diiIdentity, Instant asOf) {
        final FirstLevelHash firstLevelHash = getFirstLevelHashIdentity(diiIdentity, asOf);
        final IdentityMapResponseItem identityMapResponseItem = generateRawUid(firstLevelHash, asOf);

        final AdvertisingTokenRequest token = this.encoder.decodeAdvertisingToken(advertisingToken);
        return Arrays.equals(identityMapResponseItem.rawUid, token.rawUid.rawUid());
    }

    @Override
    public Instant getLatestOptoutEntry(HashedDii hashedDii, Instant asOf) {
        final FirstLevelHash firstLevelHash = getFirstLevelHashIdentity(hashedDii, asOf);
        return this.optOutStore.getLatestEntry(firstLevelHash);
    }

    @Override
    public Duration getIdentityExpiryDuration() {
        return this.identityExpiresAfter;
    }

    private FirstLevelHash getFirstLevelHashIdentity(HashedDii hashedDii, Instant asOf) {
        return getFirstLevelHashIdentity(hashedDii.identityScope(), hashedDii.identityType(), hashedDii.hashedDii(), asOf);
    }

    private FirstLevelHash getFirstLevelHashIdentity(IdentityScope identityScope, IdentityType identityType, byte[] identityHash, Instant asOf) {
        final byte[] firstLevelHash = getFirstLevelHash(identityHash, asOf);
        return new FirstLevelHash(identityScope, identityType, firstLevelHash, null);
    }

    private byte[] getFirstLevelHash(byte[] identityHash, Instant asOf) {
        return TokenUtils.getFirstLevelHash(identityHash, getSaltProviderSnapshot(asOf).getFirstLevelSalt());
    }

    private IdentityMapResponseItem generateRawUid(FirstLevelHash firstLevelHash, Instant asOf) {
        final SaltEntry rotatingSalt = getSaltProviderSnapshot(asOf).getRotatingSalt(firstLevelHash.firstLevelHash());

        return new IdentityMapResponseItem(
                this.identityV3Enabled
                    ? TokenUtils.getRawUidV3(firstLevelHash.identityScope(),
                        firstLevelHash.identityType(), firstLevelHash.firstLevelHash(), rotatingSalt.getSalt())
                    : TokenUtils.getRawUidV2(firstLevelHash.firstLevelHash(), rotatingSalt.getSalt()),
                rotatingSalt.getHashedId());
    }

    private TokenGenerateResponse generateIdentity(SourcePublisher sourcePublisher,
                                                   FirstLevelHash firstLevelHash, PrivacyBits privacyBits) {
        final Instant nowUtc = EncodingUtils.NowUTCMillis(this.clock);

        final IdentityMapResponseItem identityMapResponseItem = generateRawUid(firstLevelHash, nowUtc);
        final RawUid rawUid = new RawUid(firstLevelHash.identityScope(),
                firstLevelHash.identityType(),
                identityMapResponseItem.rawUid);

        return this.encoder.encodeIntoIdentityResponse(
                this.createAdvertisingTokenRequest(sourcePublisher, rawUid, nowUtc, privacyBits,
                        firstLevelHash.establishedAt()),
                this.createTokenRefreshRequest(sourcePublisher, firstLevelHash, nowUtc, privacyBits),
                nowUtc.plusMillis(refreshIdentityAfter.toMillis()),
                nowUtc
        );
    }

    private TokenRefreshRequest createTokenRefreshRequest(SourcePublisher sourcePublisher,
                                                          FirstLevelHash firstLevelHash,
                                                          Instant now,
                                                          PrivacyBits privacyBits) {
        return new TokenRefreshRequest(
                this.refreshTokenVersion,
                now,
                now.plusMillis(refreshExpiresAfter.toMillis()),
                this.operatorIdentity,
                sourcePublisher,
                firstLevelHash,
                privacyBits);
    }

    private AdvertisingTokenRequest createAdvertisingTokenRequest(SourcePublisher sourcePublisher, RawUid rawUidIdentity,
                                                                  Instant now, PrivacyBits privacyBits, Instant establishedAt) {
        TokenVersion tokenVersion;
        if (siteIdsUsingV4Tokens.contains(sourcePublisher.siteId)) {
            tokenVersion = TokenVersion.V4;
        } else {
            int pseudoRandomNumber = 1;
            final var rawUid = rawUidIdentity.rawUid();
            if (rawUid.length > 2)
            {
                int hash = ((rawUid[0] & 0xFF) << 12) | ((rawUid[1] & 0xFF) << 4) | ((rawUid[2] & 0xFF) & 0xF); //using same logic as ModBasedSaltEntryIndexer.getIndex() in uid2-shared
                pseudoRandomNumber = (hash % 100) + 1; //1 to 100
            }
            tokenVersion = (pseudoRandomNumber <= this.advertisingTokenV4Percentage) ? TokenVersion.V4 : this.tokenVersionToUseIfNotV4;
        }
        return new AdvertisingTokenRequest(tokenVersion, now, now.plusMillis(identityExpiresAfter.toMillis()), this.operatorIdentity, sourcePublisher, rawUidIdentity,
                privacyBits, establishedAt);
    }

    static protected class GlobalOptoutResult {
        private final boolean isOptedOut;
        //can be null if isOptedOut is false!
        private final Instant time;

        //providedTime can be null if isOptedOut is false!
        GlobalOptoutResult(Instant providedTime)
        {
            isOptedOut = providedTime != null;
            time = providedTime;
        }

        public boolean isOptedOut() {
            return isOptedOut;
        }

        public Instant getTime() {
            return time;
        }
    }

    private GlobalOptoutResult getGlobalOptOutResult(FirstLevelHash firstLevelHash, boolean forRefresh) {
        if (forRefresh && (firstLevelHash.matches(testRefreshOptOutIdentityForEmail) || firstLevelHash.matches(testRefreshOptOutIdentityForPhone))) {
            return new GlobalOptoutResult(Instant.now());
        } else if (firstLevelHash.matches(testValidateIdentityForEmail) || firstLevelHash.matches(testValidateIdentityForPhone)
        || firstLevelHash.matches(testRefreshOptOutIdentityForEmail) || firstLevelHash.matches(testRefreshOptOutIdentityForPhone)) {
            return new GlobalOptoutResult(null);
        } else if (firstLevelHash.matches(testOptOutIdentityForEmail) || firstLevelHash.matches(testOptOutIdentityForPhone)) {
            return new GlobalOptoutResult(Instant.now());
        }
        Instant result = this.optOutStore.getLatestEntry(firstLevelHash);
        return new GlobalOptoutResult(result);
    }
}
