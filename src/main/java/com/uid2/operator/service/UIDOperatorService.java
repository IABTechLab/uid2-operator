package com.uid2.operator.service;

import com.uid2.operator.model.*;
import com.uid2.operator.model.identities.*;
import com.uid2.operator.util.PrivacyBits;
import com.uid2.shared.audit.UidInstanceIdProvider;
import com.uid2.shared.model.SaltEntry;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.shared.store.salt.ISaltProvider;
import com.uid2.shared.model.TokenVersion;
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
import static com.uid2.operator.model.identities.IdentityConst.*;
import static java.time.temporal.ChronoUnit.DAYS;

public class UIDOperatorService implements IUIDOperatorService {
    public static final String IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS = "identity_token_expires_after_seconds";
    public static final String REFRESH_TOKEN_EXPIRES_AFTER_SECONDS = "refresh_token_expires_after_seconds";
    public static final String REFRESH_IDENTITY_TOKEN_AFTER_SECONDS = "refresh_identity_token_after_seconds";
    private static final Logger LOGGER = LoggerFactory.getLogger(UIDOperatorService.class);

    private static final Instant REFRESH_CUTOFF = LocalDateTime.parse("2021-03-08T17:00:00", DateTimeFormatter.ISO_LOCAL_DATE_TIME).toInstant(ZoneOffset.UTC);
    private static final long DAY_IN_MS = Duration.ofDays(1).toMillis();

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

    private final OperatorIdentity operatorIdentity;
    private final TokenVersion refreshTokenVersion;
    // if we use Raw UID v3 format for the raw UID2/EUIDs generated in this operator
    private final boolean rawUidV3Enabled;

    private final Handler<Boolean> saltRetrievalResponseHandler;
    private final UidInstanceIdProvider uidInstanceIdProvider;

    public UIDOperatorService(IOptOutStore optOutStore, ISaltProvider saltProvider, EncryptedTokenEncoder encoder, Clock clock,
                              IdentityScope identityScope, Handler<Boolean> saltRetrievalResponseHandler, boolean identityV3Enabled, UidInstanceIdProvider uidInstanceIdProvider) {
        this.saltProvider = saltProvider;
        this.encoder = encoder;
        this.optOutStore = optOutStore;
        this.clock = clock;
        this.identityScope = identityScope;
        this.saltRetrievalResponseHandler = saltRetrievalResponseHandler;
        this.uidInstanceIdProvider = uidInstanceIdProvider;

        this.testOptOutIdentityForEmail = getFirstLevelHashIdentity(identityScope, DiiType.Email,
                InputUtil.normalizeEmail(OptOutIdentityForEmail).getHashedDiiInput(), Instant.now());
        this.testOptOutIdentityForPhone = getFirstLevelHashIdentity(identityScope, DiiType.Phone,
                InputUtil.normalizePhone(OptOutIdentityForPhone).getHashedDiiInput(), Instant.now());
        this.testValidateIdentityForEmail = getFirstLevelHashIdentity(identityScope, DiiType.Email,
                InputUtil.normalizeEmail(ValidateIdentityForEmail).getHashedDiiInput(), Instant.now());
        this.testValidateIdentityForPhone = getFirstLevelHashIdentity(identityScope, DiiType.Phone,
                InputUtil.normalizePhone(ValidateIdentityForPhone).getHashedDiiInput(), Instant.now());
        this.testRefreshOptOutIdentityForEmail = getFirstLevelHashIdentity(identityScope, DiiType.Email,
                InputUtil.normalizeEmail(RefreshOptOutIdentityForEmail).getHashedDiiInput(), Instant.now());
        this.testRefreshOptOutIdentityForPhone = getFirstLevelHashIdentity(identityScope, DiiType.Phone,
                InputUtil.normalizePhone(RefreshOptOutIdentityForPhone).getHashedDiiInput(), Instant.now());

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
    public TokenGenerateResponse generateIdentity(TokenGenerateRequest request, Duration refreshIdentityAfter, Duration refreshExpiresAfter, Duration identityExpiresAfter) {
        this.validateTokenDurations(refreshIdentityAfter, refreshExpiresAfter, identityExpiresAfter);
        final Instant now = EncodingUtils.NowUTCMillis(this.clock);
        final byte[] firstLevelHash = getFirstLevelHash(request.hashedDii.hashedDii(), now);
        final FirstLevelHash firstLevelHashIdentity = new FirstLevelHash(
                request.hashedDii.identityScope(), request.hashedDii.diiType(), firstLevelHash,
                request.establishedAt);

        if (request.shouldCheckOptOut() && getGlobalOptOutResult(firstLevelHashIdentity, false).isOptedOut()) {
            return TokenGenerateResponse.OptOutResponse;
        } else {
            return this.generateIdentity(request.sourcePublisher, firstLevelHashIdentity, request.privacyBits, refreshIdentityAfter, refreshExpiresAfter, identityExpiresAfter);
        }
    }

    @Override
    public TokenRefreshResponse refreshIdentity(TokenRefreshRequest input, Duration refreshIdentityAfter, Duration refreshExpiresAfter, Duration identityExpiresAfter) {
        this.validateTokenDurations(refreshIdentityAfter, refreshExpiresAfter, identityExpiresAfter);
        // should not be possible as different scopes should be using different keys, but just in case
        if (input.firstLevelHash.identityScope() != this.identityScope) {
            return TokenRefreshResponse.Invalid;
        }

        if (input.firstLevelHash.establishedAt().isBefore(REFRESH_CUTOFF)) {
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
                        input.privacyBits, refreshIdentityAfter, refreshExpiresAfter, identityExpiresAfter);
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
    public IdentityMapResponseItem map(HashedDii hashedDii, Instant asOf) {
        final FirstLevelHash firstLevelHash = getFirstLevelHashIdentity(hashedDii, asOf);
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
    public void invalidateTokensAsync(HashedDii diiIdentity, Instant asOf, String uidTraceId, Handler<AsyncResult<Instant>> handler) {
        final FirstLevelHash firstLevelHash = getFirstLevelHashIdentity(diiIdentity, asOf);
        final IdentityMapResponseItem identityMapResponseItem = generateRawUid(firstLevelHash, asOf);

        this.optOutStore.addEntry(firstLevelHash, identityMapResponseItem.rawUid, uidTraceId, this.uidInstanceIdProvider.getInstanceId(),  r -> {
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

    private FirstLevelHash getFirstLevelHashIdentity(HashedDii hashedDii, Instant asOf) {
        return getFirstLevelHashIdentity(hashedDii.identityScope(), hashedDii.diiType(), hashedDii.hashedDii(), asOf);
    }

    private FirstLevelHash getFirstLevelHashIdentity(IdentityScope identityScope, DiiType diiType, byte[] hashedDii, Instant asOf) {
        final byte[] firstLevelHash = getFirstLevelHash(hashedDii, asOf);
        return new FirstLevelHash(identityScope, diiType, firstLevelHash, null);
    }

    private byte[] getFirstLevelHash(byte[] hashedDii, Instant asOf) {
        return TokenUtils.getFirstLevelHashFromHashedDii(hashedDii, getSaltProviderSnapshot(asOf).getFirstLevelSalt());
    }


    private IdentityMapResponseItem generateRawUid(FirstLevelHash firstLevelHash, Instant asOf) {
        final SaltEntry rotatingSalt = getSaltProviderSnapshot(asOf).getRotatingSalt(firstLevelHash.firstLevelHash());
        final byte[] advertisingId = getAdvertisingId(firstLevelHash, rotatingSalt.currentSalt());
        final byte[] previousAdvertisingId = getPreviousAdvertisingId(firstLevelHash, rotatingSalt, asOf);
        final long refreshFrom = getRefreshFrom(rotatingSalt, asOf);

        return new IdentityMapResponseItem(
                advertisingId,
                rotatingSalt.hashedId(),
                previousAdvertisingId,
                refreshFrom);
    }

    private byte[] getAdvertisingId(FirstLevelHash firstLevelHash, String salt) {
        return rawUidV3Enabled
                ? TokenUtils.getRawUidV3(firstLevelHash.identityScope(), firstLevelHash.diiType(),
                firstLevelHash.firstLevelHash(), salt)
                : TokenUtils.getRawUidV2(firstLevelHash.firstLevelHash(), salt);
    }

    private byte[] getPreviousAdvertisingId(FirstLevelHash firstLevelHash, SaltEntry rotatingSalt, Instant asOf) {
        long age = asOf.toEpochMilli() - rotatingSalt.lastUpdated();
        if (age / DAY_IN_MS < 90) {
            if (rotatingSalt.previousSalt() == null || rotatingSalt.previousSalt().isBlank()) {
                return null;
            }
            return getAdvertisingId(firstLevelHash, rotatingSalt.previousSalt());
        }
        return null;
    }

    private long getRefreshFrom(SaltEntry rotatingSalt, Instant asOf) {
        Long refreshFrom = rotatingSalt.refreshFrom();
        if (refreshFrom == null || refreshFrom < asOf.toEpochMilli()) {
            return asOf.truncatedTo(DAYS).plus(1, DAYS).toEpochMilli();
        }
        return refreshFrom;
    }

    private TokenGenerateResponse generateIdentity(SourcePublisher sourcePublisher,
                                                   FirstLevelHash firstLevelHash, PrivacyBits privacyBits,
                                                   Duration refreshIdentityAfter, Duration refreshExpiresAfter, Duration identityExpiresAfter) {
        final Instant nowUtc = EncodingUtils.NowUTCMillis(this.clock);

        final IdentityMapResponseItem identityMapResponseItem = generateRawUid(firstLevelHash, nowUtc);
        final RawUid rawUid = new RawUid(firstLevelHash.identityScope(),
                firstLevelHash.diiType(),
                identityMapResponseItem.rawUid);

        return this.encoder.encodeIntoIdentityResponse(
                this.createAdvertisingTokenRequest(sourcePublisher, rawUid, nowUtc, privacyBits,
                        firstLevelHash.establishedAt(), identityExpiresAfter),
                this.createTokenRefreshRequest(sourcePublisher, firstLevelHash, nowUtc, privacyBits, refreshExpiresAfter),
                nowUtc.plusMillis(refreshIdentityAfter.toMillis()),
                nowUtc
        );
    }

    private TokenRefreshRequest createTokenRefreshRequest(SourcePublisher sourcePublisher,
                                                          FirstLevelHash firstLevelHash,
                                                          Instant now,
                                                          PrivacyBits privacyBits, Duration refreshExpiresAfter) {
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
                                                                  Instant now, PrivacyBits privacyBits, Instant establishedAt, Duration identityExpiresAfter) {

        return new AdvertisingTokenRequest(TokenVersion.V4, now, now.plusMillis(identityExpiresAfter.toMillis()),
                this.operatorIdentity, sourcePublisher, rawUidIdentity,
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
