package com.uid2.operator.service;

import com.uid2.operator.model.*;
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
    private final ITokenEncoder encoder;
    private final Clock clock;
    private final IdentityScope identityScope;
    private final UserIdentity testOptOutIdentityForEmail;
    private final UserIdentity testOptOutIdentityForPhone;
    private final UserIdentity testValidateIdentityForEmail;
    private final UserIdentity testValidateIdentityForPhone;
    private final UserIdentity testRefreshOptOutIdentityForEmail;
    private final UserIdentity testRefreshOptOutIdentityForPhone;
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

    public UIDOperatorService(JsonObject config, IOptOutStore optOutStore, ISaltProvider saltProvider, ITokenEncoder encoder, Clock clock,
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
    public IdentityTokens generateIdentity(IdentityRequest request) {
        final Instant now = EncodingUtils.NowUTCMillis(this.clock);
        final byte[] firstLevelHash = getFirstLevelHash(request.userIdentity.id, now);
        final UserIdentity firstLevelHashIdentity = new UserIdentity(
                request.userIdentity.identityScope, request.userIdentity.identityType, firstLevelHash, request.userIdentity.privacyBits,
                request.userIdentity.establishedAt, request.userIdentity.refreshedAt);

        if (request.shouldCheckOptOut() && getGlobalOptOutResult(firstLevelHashIdentity, false).isOptedOut()) {
            return IdentityTokens.LogoutToken;
        } else {
            return generateIdentity(request.publisherIdentity, firstLevelHashIdentity);
        }
    }

    @Override
    public RefreshResponse refreshIdentity(RefreshToken token) {
        // should not be possible as different scopes should be using different keys, but just in case
        if (token.userIdentity.identityScope != this.identityScope) {
            return RefreshResponse.Invalid;
        }

        if (token.userIdentity.establishedAt.isBefore(RefreshCutoff)) {
            return RefreshResponse.Deprecated;
        }

        final Instant now = clock.instant();

        if (token.expiresAt.isBefore(now)) {
            return RefreshResponse.Expired;
        }

        final PrivacyBits privacyBits = PrivacyBits.fromInt(token.userIdentity.privacyBits);
        final boolean isCstg = privacyBits.isClientSideTokenGenerated();

        try {
            final GlobalOptoutResult logoutEntry = getGlobalOptOutResult(token.userIdentity, true);
            final boolean optedOut = logoutEntry.isOptedOut();

            final Duration durationSinceLastRefresh = Duration.between(token.createdAt, now);

            if (!optedOut) {
                IdentityTokens identityTokens = this.generateIdentity(token.publisherIdentity, token.userIdentity);

                return RefreshResponse.createRefreshedResponse(identityTokens, durationSinceLastRefresh, isCstg);
            } else {
                return RefreshResponse.Optout;
            }
        } catch (KeyManager.NoActiveKeyException e) {
            return RefreshResponse.NoActiveKey;
        } catch (Exception ex) {
            return RefreshResponse.Invalid;
        }
    }

    @Override
    public MappedIdentity mapIdentity(MapRequest request) {
        final UserIdentity firstLevelHashIdentity = getFirstLevelHashIdentity(request.userIdentity, request.asOf);
        if (request.shouldCheckOptOut() && getGlobalOptOutResult(firstLevelHashIdentity, false).isOptedOut()) {
            return MappedIdentity.LogoutIdentity;
        } else {
            return getAdvertisingId(firstLevelHashIdentity, request.asOf);
        }
    }

    @Override
    public MappedIdentity map(UserIdentity userIdentity, Instant asOf) {
        final UserIdentity firstLevelHashIdentity = getFirstLevelHashIdentity(userIdentity, asOf);
        return getAdvertisingId(firstLevelHashIdentity, asOf);
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
    public void invalidateTokensAsync(UserIdentity userIdentity, Instant asOf, Handler<AsyncResult<Instant>> handler) {
        final UserIdentity firstLevelHashIdentity = getFirstLevelHashIdentity(userIdentity, asOf);
        final MappedIdentity mappedIdentity = getAdvertisingId(firstLevelHashIdentity, asOf);

        this.optOutStore.addEntry(firstLevelHashIdentity, mappedIdentity.advertisingId, r -> {
            if (r.succeeded()) {
                handler.handle(Future.succeededFuture(r.result()));
            } else {
                handler.handle(Future.failedFuture(r.cause()));
            }
        });
    }

    @Override
    public boolean advertisingTokenMatches(String advertisingToken, UserIdentity userIdentity, Instant asOf) {
        final UserIdentity firstLevelHashIdentity = getFirstLevelHashIdentity(userIdentity, asOf);
        final MappedIdentity mappedIdentity = getAdvertisingId(firstLevelHashIdentity, asOf);

        final AdvertisingToken token = this.encoder.decodeAdvertisingToken(advertisingToken);
        return Arrays.equals(mappedIdentity.advertisingId, token.userIdentity.id);
    }

    @Override
    public Instant getLatestOptoutEntry(UserIdentity userIdentity, Instant asOf) {
        final UserIdentity firstLevelHashIdentity = getFirstLevelHashIdentity(userIdentity, asOf);
        return this.optOutStore.getLatestEntry(firstLevelHashIdentity);
    }

    @Override
    public Duration getIdentityExpiryDuration() {
        return this.identityExpiresAfter;
    }

    private UserIdentity getFirstLevelHashIdentity(UserIdentity userIdentity, Instant asOf) {
        return getFirstLevelHashIdentity(userIdentity.identityScope, userIdentity.identityType, userIdentity.id, asOf);
    }

    private UserIdentity getFirstLevelHashIdentity(IdentityScope identityScope, IdentityType identityType, byte[] identityHash, Instant asOf) {
        final byte[] firstLevelHash = getFirstLevelHash(identityHash, asOf);
        return new UserIdentity(identityScope, identityType, firstLevelHash, 0, null, null);
    }

    private byte[] getFirstLevelHash(byte[] identityHash, Instant asOf) {
        return TokenUtils.getFirstLevelHash(identityHash, getSaltProviderSnapshot(asOf).getFirstLevelSalt());
    }

    private MappedIdentity getAdvertisingId(UserIdentity firstLevelHashIdentity, Instant asOf) {
        final SaltEntry rotatingSalt = getSaltProviderSnapshot(asOf).getRotatingSalt(firstLevelHashIdentity.id);

        return new MappedIdentity(
                this.identityV3Enabled
                    ? TokenUtils.getAdvertisingIdV3(firstLevelHashIdentity.identityScope, firstLevelHashIdentity.identityType, firstLevelHashIdentity.id, rotatingSalt.getSalt())
                    : TokenUtils.getAdvertisingIdV2(firstLevelHashIdentity.id, rotatingSalt.getSalt()),
                rotatingSalt.getHashedId());
    }

    private IdentityTokens generateIdentity(PublisherIdentity publisherIdentity, UserIdentity firstLevelHashIdentity) {
        final Instant nowUtc = EncodingUtils.NowUTCMillis(this.clock);

        final MappedIdentity mappedIdentity = getAdvertisingId(firstLevelHashIdentity, nowUtc);
        final UserIdentity advertisingIdentity = new UserIdentity(firstLevelHashIdentity.identityScope, firstLevelHashIdentity.identityType,
                mappedIdentity.advertisingId, firstLevelHashIdentity.privacyBits, firstLevelHashIdentity.establishedAt, nowUtc);

        return this.encoder.encode(
                this.createAdvertisingToken(publisherIdentity, advertisingIdentity, nowUtc),
                this.createRefreshToken(publisherIdentity, firstLevelHashIdentity, nowUtc),
                nowUtc.plusMillis(refreshIdentityAfter.toMillis()),
                nowUtc
        );
    }

    private RefreshToken createRefreshToken(PublisherIdentity publisherIdentity, UserIdentity userIdentity, Instant now) {
        return new RefreshToken(
                this.refreshTokenVersion,
                now,
                now.plusMillis(refreshExpiresAfter.toMillis()),
                this.operatorIdentity,
                publisherIdentity,
                userIdentity);
    }

    private AdvertisingToken createAdvertisingToken(PublisherIdentity publisherIdentity, UserIdentity userIdentity, Instant now) {
        TokenVersion tokenVersion;
        if (siteIdsUsingV4Tokens.contains(publisherIdentity.siteId)) {
            tokenVersion = TokenVersion.V4;
        } else {
            int pseudoRandomNumber = 1;
            final var rawUid = userIdentity.id;
            if (rawUid.length > 2)
            {
                int hash = ((rawUid[0] & 0xFF) << 12) | ((rawUid[1] & 0xFF) << 4) | ((rawUid[2] & 0xFF) & 0xF); //using same logic as ModBasedSaltEntryIndexer.getIndex() in uid2-shared
                pseudoRandomNumber = (hash % 100) + 1; //1 to 100
            }
            tokenVersion = (pseudoRandomNumber <= this.advertisingTokenV4Percentage) ? TokenVersion.V4 : this.tokenVersionToUseIfNotV4;
        }
        return new AdvertisingToken(tokenVersion, now, now.plusMillis(identityExpiresAfter.toMillis()), this.operatorIdentity, publisherIdentity, userIdentity);
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

    private GlobalOptoutResult getGlobalOptOutResult(UserIdentity userIdentity, boolean forRefresh) {
        if (forRefresh && (userIdentity.matches(testRefreshOptOutIdentityForEmail) || userIdentity.matches(testRefreshOptOutIdentityForPhone))) {
            return new GlobalOptoutResult(Instant.now());
        } else if (userIdentity.matches(testValidateIdentityForEmail) || userIdentity.matches(testValidateIdentityForPhone)
        || userIdentity.matches(testRefreshOptOutIdentityForEmail) || userIdentity.matches(testRefreshOptOutIdentityForPhone)) {
            return new GlobalOptoutResult(null);
        } else if (userIdentity.matches(testOptOutIdentityForEmail) || userIdentity.matches(testOptOutIdentityForPhone)) {
            return new GlobalOptoutResult(Instant.now());
        }
        Instant result = this.optOutStore.getLatestEntry(userIdentity);
        return new GlobalOptoutResult(result);
    }
}
