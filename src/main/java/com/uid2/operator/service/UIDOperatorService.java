package com.uid2.operator.service;

import com.uid2.operator.model.*;
import com.uid2.operator.util.IdAndTokenVersionConfig;
import com.uid2.operator.util.PrivacyBits;
import com.uid2.shared.model.SaltEntry;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.shared.store.ISaltProvider;
import com.uid2.shared.model.TokenVersion;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class UIDOperatorService implements IUIDOperatorService {
    public static final String IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS = "identity_token_expires_after_seconds";
    public static final String REFRESH_TOKEN_EXPIRES_AFTER_SECONDS = "refresh_token_expires_after_seconds";
    public static final String REFRESH_IDENTITY_TOKEN_AFTER_SECONDS = "refresh_identity_token_after_seconds";

    private static final Instant RefreshCutoff = LocalDateTime.parse("2021-03-08T17:00:00", DateTimeFormatter.ISO_LOCAL_DATE_TIME).toInstant(ZoneOffset.UTC);
    private final ISaltProvider saltProvider;
    private final IOptOutStore optOutStore;
    private final ITokenEncoder encoder;
    private final Clock clock;
    private final IdentityScope identityScope;
    private final UserIdentity testOptOutIdentityForEmail;
    private final UserIdentity testOptOutIdentityForPhone;
    private final Duration identityExpiresAfter;
    private final Duration refreshExpiresAfter;
    private final Duration refreshIdentityAfter;
    private final OperatorIdentity operatorIdentity;

    private final IdAndTokenVersionConfig serverSidetokenGenerateVersionConfig;
    private final IdAndTokenVersionConfig clientSideTokenGenerateVersionConfig;

    public UIDOperatorService(JsonObject config, IOptOutStore optOutStore, ISaltProvider saltProvider, ITokenEncoder encoder, Clock clock, IdentityScope identityScope) {
        this.saltProvider = saltProvider;
        this.encoder = encoder;
        this.optOutStore = optOutStore;
        this.clock = clock;
        this.identityScope = identityScope;

        this.testOptOutIdentityForEmail = getFirstLevelHashIdentity(identityScope, IdentityType.Email,
                InputUtil.normalizeEmail("optout@email.com").getIdentityInput(), Instant.now());
        this.testOptOutIdentityForPhone = getFirstLevelHashIdentity(identityScope, IdentityType.Phone,
                InputUtil.normalizePhone("+00000000000").getIdentityInput(), Instant.now());


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

        TokenVersion advertisingTokenVersion;
        if (config.getBoolean("advertising_token_v4", false)) {
            advertisingTokenVersion = TokenVersion.V4;
        } else {
            advertisingTokenVersion = config.getBoolean("advertising_token_v3", false) ? TokenVersion.V3 : TokenVersion.V2;
        }
        TokenVersion refreshTokenVersion = config.getBoolean("refresh_token_v3", false) ? TokenVersion.V3 : TokenVersion.V2;
        boolean identityV3Enabled = config.getBoolean("identity_v3", false);
        this.serverSidetokenGenerateVersionConfig = new IdAndTokenVersionConfig(identityV3Enabled, advertisingTokenVersion, refreshTokenVersion);
        //TODO should we use Refresh Token v3 and server side's identityV3Enabled config?
        this.clientSideTokenGenerateVersionConfig = new IdAndTokenVersionConfig(identityV3Enabled, TokenVersion.V4, TokenVersion.V3);
    }

    @Override
    public IdentityTokens generateIdentity(IdentityRequest request, boolean cstg) {
        final Instant now = EncodingUtils.NowUTCMillis(this.clock);
        final byte[] firstLevelHash = getFirstLevelHash(request.userIdentity.id, now);
        final UserIdentity firstLevelHashIdentity = new UserIdentity(
                request.userIdentity.identityScope, request.userIdentity.identityType, firstLevelHash, request.userIdentity.privacyBits,
                request.userIdentity.establishedAt, request.userIdentity.refreshedAt);

        if (request.shouldCheckOptOut() && hasGlobalOptOut(firstLevelHashIdentity)) {
            return IdentityTokens.LogoutToken;
        } else {
            IdAndTokenVersionConfig versionConfig = cstg? clientSideTokenGenerateVersionConfig : serverSidetokenGenerateVersionConfig;
            return generateIdentity(request.publisherIdentity, firstLevelHashIdentity, versionConfig);
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

        if (token.expiresAt.isBefore(Instant.now(this.clock))) {
            return RefreshResponse.Expired;
        }

        if (token.userIdentity.matches(testOptOutIdentityForEmail) || token.userIdentity.matches(testOptOutIdentityForPhone)) {
            return RefreshResponse.Optout;
        }

        try {
            final Instant logoutEntry = this.optOutStore.getLatestEntry(token.userIdentity);
            IdAndTokenVersionConfig idAndTokenVersionConfig = PrivacyBits.fromInt(token.userIdentity.privacyBits).isClientSideTokenGenerateBitSet() ?
                    clientSideTokenGenerateVersionConfig : serverSidetokenGenerateVersionConfig;

            if (logoutEntry == null || token.userIdentity.establishedAt.isAfter(logoutEntry)) {
                Duration durationSinceLastRefresh = Duration.between(token.createdAt, Instant.now(this.clock));
                return RefreshResponse.Refreshed(this.generateIdentity(token.publisherIdentity, token.userIdentity, idAndTokenVersionConfig)
                        , durationSinceLastRefresh);
            } else {
                return RefreshResponse.Optout;
            }
        } catch (Exception ex) {
            return RefreshResponse.Invalid;
        }
    }

    @Override
    public MappedIdentity mapIdentity(MapRequest request) {
        final UserIdentity firstLevelHashIdentity = getFirstLevelHashIdentity(request.userIdentity, request.asOf);
        if (request.shouldCheckOptOut() && hasGlobalOptOut(firstLevelHashIdentity)) {
            return MappedIdentity.LogoutIdentity;
        } else {
            return getAdvertisingId(firstLevelHashIdentity, request.asOf, serverSidetokenGenerateVersionConfig.identityV3Enabled);
        }
    }

    @Override
    public MappedIdentity map(UserIdentity userIdentity, Instant asOf) {
        final UserIdentity firstLevelHashIdentity = getFirstLevelHashIdentity(userIdentity, asOf);
        return getAdvertisingId(firstLevelHashIdentity, asOf, serverSidetokenGenerateVersionConfig.identityV3Enabled);
    }

    @Override
    public List<SaltEntry> getModifiedBuckets(Instant sinceTimestamp) {
        return this.saltProvider.getSnapshot(Instant.now()).getModifiedSince(sinceTimestamp);
    }

    @Override
    public void invalidateTokensAsync(UserIdentity userIdentity, Instant asOf, Handler<AsyncResult<Instant>> handler) {
        final UserIdentity firstLevelHashIdentity = getFirstLevelHashIdentity(userIdentity, asOf);
        final MappedIdentity mappedIdentity = getAdvertisingId(firstLevelHashIdentity, asOf, serverSidetokenGenerateVersionConfig.identityV3Enabled);

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
        final MappedIdentity mappedIdentity = getAdvertisingId(firstLevelHashIdentity, asOf, serverSidetokenGenerateVersionConfig.identityV3Enabled);

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

    @Override
    public UserIdentity getFirstLevelHashIdentity(IdentityScope identityScope, IdentityType identityType, byte[] identityHash, Instant asOf) {
        final byte[] firstLevelHash = getFirstLevelHash(identityHash, asOf);
        return new UserIdentity(identityScope, identityType, firstLevelHash, 0, null, null);
    }

    private byte[] getFirstLevelHash(byte[] identityHash, Instant asOf) {
        return TokenUtils.getFirstLevelHash(identityHash, this.saltProvider.getSnapshot(asOf).getFirstLevelSalt());
    }

    private MappedIdentity getAdvertisingId(UserIdentity firstLevelHashIdentity, Instant asOf, boolean identityV3Enabled) {
        final SaltEntry rotatingSalt = this.saltProvider.getSnapshot(asOf).getRotatingSalt(firstLevelHashIdentity.id);

        return new MappedIdentity(
                identityV3Enabled
                    ? TokenUtils.getAdvertisingIdV3(firstLevelHashIdentity.identityScope, firstLevelHashIdentity.identityType, firstLevelHashIdentity.id, rotatingSalt.getSalt())
                    : TokenUtils.getAdvertisingIdV2(firstLevelHashIdentity.id, rotatingSalt.getSalt()),
                rotatingSalt.getHashedId());
    }

    private IdentityTokens generateIdentity(PublisherIdentity publisherIdentity, UserIdentity firstLevelHashIdentity, IdAndTokenVersionConfig idAndTokenVersionConfig) {
        final Instant nowUtc = EncodingUtils.NowUTCMillis(this.clock);

        final MappedIdentity mappedIdentity = getAdvertisingId(firstLevelHashIdentity, nowUtc, idAndTokenVersionConfig.identityV3Enabled);
        final UserIdentity advertisingIdentity = new UserIdentity(firstLevelHashIdentity.identityScope, firstLevelHashIdentity.identityType,
                mappedIdentity.advertisingId, firstLevelHashIdentity.privacyBits, firstLevelHashIdentity.establishedAt, nowUtc);

        return this.encoder.encode(
                this.createAdvertisingToken(publisherIdentity, advertisingIdentity, nowUtc, idAndTokenVersionConfig.advertisingTokenVersion),
                this.createRefreshToken(publisherIdentity, firstLevelHashIdentity, nowUtc, idAndTokenVersionConfig.refreshTokenVersion),
                nowUtc.plusMillis(refreshIdentityAfter.toMillis()),
                nowUtc
        );
    }

    private RefreshToken createRefreshToken(PublisherIdentity publisherIdentity, UserIdentity userIdentity, Instant now, TokenVersion refreshTokenVersion) {
        return new RefreshToken(
                refreshTokenVersion,
                now,
                now.plusMillis(refreshExpiresAfter.toMillis()),
                this.operatorIdentity,
                publisherIdentity,
                userIdentity);
    }

    private AdvertisingToken createAdvertisingToken(PublisherIdentity publisherIdentity, UserIdentity userIdentity, Instant now, TokenVersion advertisingTokenVersion) {
        return new AdvertisingToken(
                advertisingTokenVersion,
                now,
                now.plusMillis(identityExpiresAfter.toMillis()),
                this.operatorIdentity,
                publisherIdentity,
                userIdentity);
    }

    private boolean hasGlobalOptOut(UserIdentity userIdentity) {
        return this.optOutStore.getLatestEntry(userIdentity) != null;
    }

}
