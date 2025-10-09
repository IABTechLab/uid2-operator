package com.uid2.operator.service;

import com.uid2.operator.model.*;
import com.uid2.operator.util.PrivacyBits;
import com.uid2.shared.audit.UidInstanceIdProvider;
import com.uid2.shared.model.SaltEntry;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.shared.store.salt.ISaltProvider;
import com.uid2.shared.model.TokenVersion;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
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
import static java.time.temporal.ChronoUnit.DAYS;

public class UIDOperatorService implements IUIDOperatorService {
    public static final Logger LOGGER = LoggerFactory.getLogger(UIDOperatorService.class);

    public static final String IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS = "identity_token_expires_after_seconds";
    public static final String REFRESH_TOKEN_EXPIRES_AFTER_SECONDS = "refresh_token_expires_after_seconds";
    public static final String REFRESH_IDENTITY_TOKEN_AFTER_SECONDS = "refresh_identity_token_after_seconds";

    private static final Instant REFRESH_CUTOFF = LocalDateTime.parse("2021-03-08T17:00:00", DateTimeFormatter.ISO_LOCAL_DATE_TIME).toInstant(ZoneOffset.UTC);
    private static final long DAY_IN_MS = Duration.ofDays(1).toMillis();

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

    private final OperatorIdentity operatorIdentity;
    private final TokenVersion refreshTokenVersion;
    // if we use Raw UID v3 format for the raw UID2/EUIDs generated in this operator
    private final boolean rawUidV3Enabled;

    private final Handler<Boolean> saltRetrievalResponseHandler;
    private final UidInstanceIdProvider uidInstanceIdProvider;

    public UIDOperatorService(IOptOutStore optOutStore, ISaltProvider saltProvider, ITokenEncoder encoder, Clock clock,
                              IdentityScope identityScope, Handler<Boolean> saltRetrievalResponseHandler, boolean identityV3Enabled, UidInstanceIdProvider uidInstanceIdProvider) {
        this.saltProvider = saltProvider;
        this.encoder = encoder;
        this.optOutStore = optOutStore;
        this.clock = clock;
        this.identityScope = identityScope;
        this.saltRetrievalResponseHandler = saltRetrievalResponseHandler;
        this.uidInstanceIdProvider = uidInstanceIdProvider;

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

        this.refreshTokenVersion = TokenVersion.V3;
        this.rawUidV3Enabled = identityV3Enabled;
    }

    private void validateTokenDurations(Duration refreshIdentityAfter, Duration refreshExpiresAfter, Duration identityExpiresAfter) {
        if (identityExpiresAfter.compareTo(refreshExpiresAfter) > 0) {
            throw new IllegalStateException(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS + " (" + refreshExpiresAfter.toSeconds() + ") < " + IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS + " (" + identityExpiresAfter.toSeconds() + ")");
        }
        if (refreshIdentityAfter.compareTo(identityExpiresAfter) > 0) {
            throw new IllegalStateException(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS + " (" + identityExpiresAfter.toSeconds() + ") < " + REFRESH_IDENTITY_TOKEN_AFTER_SECONDS + " (" + refreshIdentityAfter.toSeconds() + ")");
        }
        if (refreshIdentityAfter.compareTo(refreshExpiresAfter) > 0) {
            throw new IllegalStateException(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS + " (" + refreshExpiresAfter.toSeconds() + ") < " + REFRESH_IDENTITY_TOKEN_AFTER_SECONDS + " (" + refreshIdentityAfter.toSeconds() + ")");
        }
    }

    @Override
    public IdentityTokens generateIdentity(IdentityRequest request, Duration refreshIdentityAfter, Duration refreshExpiresAfter, Duration identityExpiresAfter) {
        this.validateTokenDurations(refreshIdentityAfter, refreshExpiresAfter, identityExpiresAfter);
        final Instant now = EncodingUtils.NowUTCMillis(this.clock);
        final byte[] firstLevelHash = getFirstLevelHash(request.userIdentity.id, now);
        final UserIdentity firstLevelHashIdentity = new UserIdentity(
                request.userIdentity.identityScope, request.userIdentity.identityType, firstLevelHash, request.userIdentity.privacyBits,
                request.userIdentity.establishedAt, request.userIdentity.refreshedAt);

        if (request.shouldCheckOptOut() && getGlobalOptOutResult(firstLevelHashIdentity, false).isOptedOut()) {
            return IdentityTokens.LogoutToken;
        } else {
            return this.generateIdentity(request.publisherIdentity, firstLevelHashIdentity, refreshIdentityAfter, refreshExpiresAfter, identityExpiresAfter, request.identityEnvironment);
        }
    }

    @Override
    public RefreshResponse refreshIdentity(RefreshToken token, Duration refreshIdentityAfter, Duration refreshExpiresAfter, Duration identityExpiresAfter, IdentityEnvironment env) {
        this.validateTokenDurations(refreshIdentityAfter, refreshExpiresAfter, identityExpiresAfter);
        // should not be possible as different scopes/environments should be using different keys, but just in case
        if (token.userIdentity.identityScope != this.identityScope) {
            return RefreshResponse.Invalid;
        }

        if (token.userIdentity.establishedAt.isBefore(REFRESH_CUTOFF)) {
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
                IdentityTokens identityTokens = this.generateIdentity(token.publisherIdentity, token.userIdentity, refreshIdentityAfter, refreshExpiresAfter, identityExpiresAfter, env);

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
            return getMappedIdentity(firstLevelHashIdentity, request.asOf, request.identityEnvironment);
        }
    }

    @Override
    public MappedIdentity map(UserIdentity userIdentity, Instant asOf, IdentityEnvironment env) {
        final UserIdentity firstLevelHashIdentity = getFirstLevelHashIdentity(userIdentity, asOf);
        return getMappedIdentity(firstLevelHashIdentity, asOf, env);
    }

    @Override
    public List<SaltEntry> getModifiedBuckets(Instant sinceTimestamp) {
        return getSaltProviderSnapshot(Instant.now()).getModifiedSince(sinceTimestamp);
    }

    private ISaltProvider.ISaltSnapshot getSaltProviderSnapshot(Instant asOf) {
        ISaltProvider.ISaltSnapshot snapshot = this.saltProvider.getSnapshot(asOf);
        if (snapshot.getExpires().isBefore(Instant.now())) {
            saltRetrievalResponseHandler.handle(true);
        } else {
            saltRetrievalResponseHandler.handle(false);
        }
        return snapshot;
    }

    @Override
    public void invalidateTokensAsync(UserIdentity userIdentity, Instant asOf, String uidTraceId, IdentityEnvironment env, Handler<AsyncResult<Instant>> handler) {
        final UserIdentity firstLevelHashIdentity = getFirstLevelHashIdentity(userIdentity, asOf);
        final MappedIdentity mappedIdentity = getMappedIdentity(firstLevelHashIdentity, asOf, env);

        this.optOutStore.addEntry(firstLevelHashIdentity, mappedIdentity.advertisingId, uidTraceId, this.uidInstanceIdProvider.getInstanceId(), r -> {
            if (r.succeeded()) {
                handler.handle(Future.succeededFuture(r.result()));
            } else {
                handler.handle(Future.failedFuture(r.cause()));
            }
        });
    }

    @Override
    public boolean advertisingTokenMatches(String advertisingToken, UserIdentity userIdentity, Instant asOf, IdentityEnvironment env) {
        final UserIdentity firstLevelHashIdentity = getFirstLevelHashIdentity(userIdentity, asOf);
        final MappedIdentity mappedIdentity = getMappedIdentity(firstLevelHashIdentity, asOf, env);

        final AdvertisingToken token = this.encoder.decodeAdvertisingToken(advertisingToken);
        return Arrays.equals(mappedIdentity.advertisingId, token.userIdentity.id);
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

    private MappedIdentity getMappedIdentity(UserIdentity firstLevelHashIdentity, Instant asOf, IdentityEnvironment env) {
        final SaltEntry rotatingSalt = getSaltProviderSnapshot(asOf).getRotatingSalt(firstLevelHashIdentity.id);
        final byte[] advertisingId = getAdvertisingId(firstLevelHashIdentity, rotatingSalt.currentSalt(), rotatingSalt.currentKeySalt(), env);
        final byte[] previousAdvertisingId = getPreviousAdvertisingId(firstLevelHashIdentity, rotatingSalt, asOf, env);
        final long refreshFrom = getRefreshFrom(rotatingSalt, asOf);

        return new MappedIdentity(
                advertisingId,
                rotatingSalt.hashedId(),
                previousAdvertisingId,
                refreshFrom);
    }

    private byte[] getAdvertisingId(UserIdentity firstLevelHashIdentity, String salt, SaltEntry.KeyMaterial key, IdentityEnvironment env) {
        byte[] advertisingId;

        if (salt != null) {
            if (rawUidV3Enabled) {
                advertisingId = TokenUtils.getAdvertisingIdV3(firstLevelHashIdentity.identityScope, firstLevelHashIdentity.identityType, firstLevelHashIdentity.id, salt);
                incrementAdvertisingIdVersionCounter("v3");
            } else {
                advertisingId = TokenUtils.getAdvertisingIdV2(firstLevelHashIdentity.id, salt);
                incrementAdvertisingIdVersionCounter("v2");
            }
        } else {
            try {
                advertisingId = TokenUtils.getAdvertisingIdV4(firstLevelHashIdentity.identityScope, firstLevelHashIdentity.identityType, env, firstLevelHashIdentity.id, key);
                incrementAdvertisingIdVersionCounter("v4");
            } catch (Exception e) {
                LOGGER.error("Exception when generating V4 advertising ID", e);
                advertisingId = null;
            }
        }

        return advertisingId;
    }

    private void incrementAdvertisingIdVersionCounter(String version) {
        Counter.builder("uid2_raw_uid_version_total")
                .description("counter for raw UID version")
                .tag("version", version)
                .register(Metrics.globalRegistry)
                .increment();
    }

    private byte[] getPreviousAdvertisingId(UserIdentity firstLevelHashIdentity, SaltEntry rotatingSalt, Instant asOf, IdentityEnvironment env) {
        long age = asOf.toEpochMilli() - rotatingSalt.lastUpdated();
        if (age / DAY_IN_MS < 90) {
            boolean missingSalt = rotatingSalt.previousSalt() == null;
            boolean missingKey = rotatingSalt.previousKeySalt() == null
                    || rotatingSalt.previousKeySalt().key() == null || rotatingSalt.previousKeySalt().salt() == null;

            if (missingSalt && missingKey) {
                return null;
            }
            return getAdvertisingId(firstLevelHashIdentity, rotatingSalt.previousSalt(), rotatingSalt.previousKeySalt(), env);
        }
        return null;
    }

    private long getRefreshFrom(SaltEntry rotatingSalt, Instant asOf) {
        long refreshFrom = rotatingSalt.refreshFrom();
        if (refreshFrom < asOf.toEpochMilli()) {
            return asOf.truncatedTo(DAYS).plus(1, DAYS).toEpochMilli();
        }
        return refreshFrom;
    }

    private IdentityTokens generateIdentity(PublisherIdentity publisherIdentity, UserIdentity firstLevelHashIdentity, Duration refreshIdentityAfter, Duration refreshExpiresAfter, Duration identityExpiresAfter, IdentityEnvironment env) {
        final Instant nowUtc = EncodingUtils.NowUTCMillis(this.clock);

        final MappedIdentity mappedIdentity = getMappedIdentity(firstLevelHashIdentity, nowUtc, env);
        final UserIdentity advertisingIdentity = new UserIdentity(firstLevelHashIdentity.identityScope, firstLevelHashIdentity.identityType,
                mappedIdentity.advertisingId, firstLevelHashIdentity.privacyBits, firstLevelHashIdentity.establishedAt, nowUtc);

        return this.encoder.encode(
                this.createAdvertisingToken(publisherIdentity, advertisingIdentity, nowUtc, identityExpiresAfter),
                this.createRefreshToken(publisherIdentity, firstLevelHashIdentity, nowUtc, refreshExpiresAfter),
                nowUtc.plusMillis(refreshIdentityAfter.toMillis()),
                nowUtc
        );
    }

    private RefreshToken createRefreshToken(PublisherIdentity publisherIdentity, UserIdentity userIdentity, Instant now, Duration refreshExpiresAfter) {
        return new RefreshToken(
                this.refreshTokenVersion,
                now,
                now.plusMillis(refreshExpiresAfter.toMillis()),
                this.operatorIdentity,
                publisherIdentity,
                userIdentity);
    }

    private AdvertisingToken createAdvertisingToken(PublisherIdentity publisherIdentity, UserIdentity userIdentity, Instant now, Duration identityExpiresAfter) {
        return new AdvertisingToken(TokenVersion.V4, now, now.plusMillis(identityExpiresAfter.toMillis()), this.operatorIdentity, publisherIdentity, userIdentity);
    }

    protected static class GlobalOptoutResult {
        private final boolean isOptedOut;
        // can be null if isOptedOut is false!
        private final Instant time;

        // providedTime can be null if isOptedOut is false!
        GlobalOptoutResult(Instant providedTime) {
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
