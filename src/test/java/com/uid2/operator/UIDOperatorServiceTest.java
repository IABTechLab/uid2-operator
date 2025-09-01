package com.uid2.operator;

import com.uid2.operator.model.*;
import com.uid2.operator.service.EncodingUtils;
import com.uid2.operator.service.EncryptedTokenEncoder;
import com.uid2.operator.service.ITokenEncoder;
import com.uid2.operator.service.InputUtil;
import com.uid2.operator.service.UIDOperatorService;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.operator.vertx.OperatorShutdownHandler;
import com.uid2.shared.audit.UidInstanceIdProvider;
import com.uid2.shared.model.SaltEntry;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.salt.ISaltProvider;
import com.uid2.shared.store.salt.RotatingSaltProvider;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.store.reader.RotatingKeysetKeyStore;
import com.uid2.shared.store.reader.RotatingKeysetProvider;
import com.uid2.shared.store.scope.GlobalScope;
import com.uid2.shared.model.TokenVersion;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.uid2.operator.Const.Config.IdentityV3Prop;
import static java.time.temporal.ChronoUnit.DAYS;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.time.*;
import java.time.temporal.ChronoUnit;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class UIDOperatorServiceTest {
    private static final String FIRST_LEVEL_SALT = "first-level-salt";
    private static final int IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS = 600;
    private static final int REFRESH_TOKEN_EXPIRES_AFTER_SECONDS = 900;
    private static final int REFRESH_IDENTITY_TOKEN_AFTER_SECONDS = 300;

    private AutoCloseable mocks;
    @Mock private IOptOutStore optOutStore;
    @Mock private Clock clock;
    @Mock private OperatorShutdownHandler shutdownHandler;

    private EncryptedTokenEncoder tokenEncoder;
    private UidInstanceIdProvider uidInstanceIdProvider;
    private JsonObject uid2Config;
    private JsonObject euidConfig;
    private ExtendedUIDOperatorService uid2Service;
    private ExtendedUIDOperatorService euidService;
    private Instant now;

    static class ExtendedUIDOperatorService extends UIDOperatorService {
        public ExtendedUIDOperatorService(IOptOutStore optOutStore, ISaltProvider saltProvider, ITokenEncoder encoder, Clock clock, IdentityScope identityScope, Handler<Boolean> saltRetrievalResponseHandler, boolean identityV3Enabled, UidInstanceIdProvider uidInstanceIdProvider) {
            super(optOutStore, saltProvider, encoder, clock, identityScope, saltRetrievalResponseHandler, identityV3Enabled, uidInstanceIdProvider);
        }
    }

    @BeforeEach
    void setup() throws Exception {
        mocks = MockitoAnnotations.openMocks(this);

        Security.setProperty("crypto.policy", "unlimited");

        RotatingKeysetKeyStore keysetKeyStore = new RotatingKeysetKeyStore(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/keyset_keys/metadata.json")));
        keysetKeyStore.loadContent();

        RotatingKeysetProvider keysetProvider = new RotatingKeysetProvider(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/keysets/metadata.json")));
        keysetProvider.loadContent();

        RotatingSaltProvider saltProvider = new RotatingSaltProvider(
                new EmbeddedResourceStorage(Main.class),
                "/com.uid2.core/test/salts/metadata.json");
        saltProvider.loadContent();

        tokenEncoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

        setNow(Instant.now());

        uid2Config = new JsonObject();
        uid2Config.put(UIDOperatorService.IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
        uid2Config.put(UIDOperatorService.REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, REFRESH_TOKEN_EXPIRES_AFTER_SECONDS);
        uid2Config.put(UIDOperatorService.REFRESH_IDENTITY_TOKEN_AFTER_SECONDS, REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
        uid2Config.put(Const.Config.IdentityEnvironmentProp, IdentityEnvironment.Test);
        uid2Config.put(IdentityV3Prop, false);

        uidInstanceIdProvider = new UidInstanceIdProvider("test-instance", "id");

        uid2Service = new ExtendedUIDOperatorService(
                optOutStore,
                saltProvider,
                tokenEncoder,
                this.clock,
                IdentityScope.UID2,
                this.shutdownHandler::handleSaltRetrievalResponse,
                uid2Config.getBoolean(IdentityV3Prop),
                uidInstanceIdProvider
        );

        euidConfig = new JsonObject();
        euidConfig.put(UIDOperatorService.IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
        euidConfig.put(UIDOperatorService.REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, REFRESH_TOKEN_EXPIRES_AFTER_SECONDS);
        euidConfig.put(UIDOperatorService.REFRESH_IDENTITY_TOKEN_AFTER_SECONDS, REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
        euidConfig.put(Const.Config.IdentityEnvironmentProp, "test");
        euidConfig.put(IdentityV3Prop, true);

        euidService = new ExtendedUIDOperatorService(
                optOutStore,
                saltProvider,
                tokenEncoder,
                this.clock,
                IdentityScope.EUID,
                this.shutdownHandler::handleSaltRetrievalResponse,
                euidConfig.getBoolean(IdentityV3Prop),
                uidInstanceIdProvider
        );
    }

    @AfterEach
    void teardown() throws Exception {
        mocks.close();
    }

    private void setNow(Instant now) {
        this.now = now.truncatedTo(ChronoUnit.MILLIS);
        when(clock.instant()).thenAnswer(i -> this.now);
    }

    private RotatingSaltProvider.SaltSnapshot setUpMockSalts() {
        RotatingSaltProvider saltProvider = mock(RotatingSaltProvider.class);
        RotatingSaltProvider.SaltSnapshot saltSnapshot = mock(RotatingSaltProvider.SaltSnapshot.class);
        when(saltProvider.getSnapshot(any())).thenReturn(saltSnapshot);
        when(saltSnapshot.getExpires()).thenReturn(Instant.now().plus(1, ChronoUnit.HOURS));
        when(saltSnapshot.getFirstLevelSalt()).thenReturn(FIRST_LEVEL_SALT);

        uid2Service = new ExtendedUIDOperatorService(
                optOutStore,
                saltProvider,
                tokenEncoder,
                this.clock,
                IdentityScope.UID2,
                this.shutdownHandler::handleSaltRetrievalResponse,
                uid2Config.getBoolean(IdentityV3Prop),
                uidInstanceIdProvider
        );

        return saltSnapshot;
    }

    private UserIdentity createUserIdentity(String rawIdentityHash, IdentityScope scope, IdentityType type) {
        return new UserIdentity(
                scope,
                type,
                rawIdentityHash.getBytes(StandardCharsets.UTF_8),
                0,
                this.now.minusSeconds(234),
                this.now.plusSeconds(12345)
        );
    }

    private AdvertisingToken validateAndGetToken(EncryptedTokenEncoder tokenEncoder, String advertisingTokenString, IdentityScope scope, IdentityType type, int siteId) {
        UIDOperatorVerticleTest.validateAdvertisingToken(advertisingTokenString, TokenVersion.V4, scope, type);
        return tokenEncoder.decodeAdvertisingToken(advertisingTokenString);
    }

    private void assertIdentityScopeIdentityTypeAndEstablishedAt(UserIdentity expctedUserIdentity, UserIdentity actualUserIdentity) {
        assertEquals(expctedUserIdentity.identityScope, actualUserIdentity.identityScope);
        assertEquals(expctedUserIdentity.identityType, actualUserIdentity.identityType);
        assertEquals(expctedUserIdentity.establishedAt, actualUserIdentity.establishedAt);
    }

    @ParameterizedTest
    @CsvSource({"123, V4", "127, V4", "128, V4"})
    void testGenerateAndRefresh(int siteId, TokenVersion tokenVersion) {
        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(siteId, 124, 125),
                createUserIdentity("test-email-hash", IdentityScope.UID2, IdentityType.Email),
                OptoutCheckPolicy.DoNotRespect,
                IdentityEnvironment.Test
        );
        final IdentityTokens tokens = uid2Service.generateIdentity(
                identityRequest,
                Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokens);

        UIDOperatorVerticleTest.validateAdvertisingToken(tokens.getAdvertisingToken(), tokenVersion, IdentityScope.UID2, IdentityType.Email);
        AdvertisingToken advertisingToken = tokenEncoder.decodeAdvertisingToken(tokens.getAdvertisingToken());
        assertEquals(this.now.plusSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS), advertisingToken.expiresAt);
        assertEquals(identityRequest.publisherIdentity.siteId, advertisingToken.publisherIdentity.siteId);
        assertIdentityScopeIdentityTypeAndEstablishedAt(identityRequest.userIdentity, advertisingToken.userIdentity);

        RefreshToken refreshToken = tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        assertEquals(this.now, refreshToken.createdAt);
        assertEquals(this.now.plusSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS), refreshToken.expiresAt);
        assertEquals(identityRequest.publisherIdentity.siteId, refreshToken.publisherIdentity.siteId);
        assertIdentityScopeIdentityTypeAndEstablishedAt(identityRequest.userIdentity, refreshToken.userIdentity);

        setNow(Instant.now().plusSeconds(200));

        reset(shutdownHandler);
        final RefreshResponse refreshResponse = uid2Service.refreshIdentity(
                refreshToken,
                Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS),
                IdentityEnvironment.Test);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(refreshResponse);
        assertEquals(RefreshResponse.Status.Refreshed, refreshResponse.getStatus());
        assertNotNull(refreshResponse.getTokens());

        UIDOperatorVerticleTest.validateAdvertisingToken(refreshResponse.getTokens().getAdvertisingToken(), tokenVersion, IdentityScope.UID2, IdentityType.Email);
        AdvertisingToken advertisingToken2 = tokenEncoder.decodeAdvertisingToken(refreshResponse.getTokens().getAdvertisingToken());
        assertEquals(this.now.plusSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS), advertisingToken2.expiresAt);
        assertEquals(advertisingToken.publisherIdentity.siteId, advertisingToken2.publisherIdentity.siteId);
        assertIdentityScopeIdentityTypeAndEstablishedAt(advertisingToken.userIdentity, advertisingToken2.userIdentity);
        assertArrayEquals(advertisingToken.userIdentity.id, advertisingToken2.userIdentity.id);

        RefreshToken refreshToken2 = tokenEncoder.decodeRefreshToken(refreshResponse.getTokens().getRefreshToken());
        assertEquals(this.now, refreshToken2.createdAt);
        assertEquals(this.now.plusSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS), refreshToken2.expiresAt);
        assertEquals(refreshToken.publisherIdentity.siteId, refreshToken2.publisherIdentity.siteId);
        assertIdentityScopeIdentityTypeAndEstablishedAt(refreshToken.userIdentity, refreshToken2.userIdentity);
        assertArrayEquals(refreshToken.userIdentity.id, refreshToken2.userIdentity.id);
    }

    @Test
    void testTestOptOutKey_DoNotRespectOptout() {
        final InputUtil.InputVal inputVal = InputUtil.normalizeEmail(IdentityConst.OptOutIdentityForEmail);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toUserIdentity(IdentityScope.UID2,0, this.now),
                OptoutCheckPolicy.DoNotRespect,
                IdentityEnvironment.Test
        );
        final IdentityTokens tokens = uid2Service.generateIdentity(
                identityRequest,
                Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokens);
        assertFalse(tokens.isEmptyToken());

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        assertEquals(RefreshResponse.Optout, uid2Service.refreshIdentity(
                refreshToken,
                Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS),
                IdentityEnvironment.Test));
    }

    @Test
    void testTestOptOutKey_RespectOptout() {
        final InputUtil.InputVal inputVal = InputUtil.normalizeEmail(IdentityConst.OptOutIdentityForEmail);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toUserIdentity(IdentityScope.UID2,0, this.now),
                OptoutCheckPolicy.RespectOptOut,
                IdentityEnvironment.Test
        );
        final IdentityTokens tokens = uid2Service.generateIdentity(
                identityRequest,
                Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        assertTrue(tokens.isEmptyToken());
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
    }

    @Test
    void testTestOptOutKeyIdentityScopeMismatch() {
        final String email = "optout@example.com";
        final InputUtil.InputVal inputVal = InputUtil.normalizeEmail(email);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toUserIdentity(IdentityScope.EUID,0, this.now),
                OptoutCheckPolicy.DoNotRespect,
                IdentityEnvironment.Test
        );
        final IdentityTokens tokens = euidService.generateIdentity(
                identityRequest,
                Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokens);

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        reset(shutdownHandler);
        assertEquals(RefreshResponse.Invalid, uid2Service.refreshIdentity(
                refreshToken,
                Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS),
                IdentityEnvironment.Test));
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(anyBoolean());
    }

    @ParameterizedTest
    @CsvSource({
            "Email,test@example.com,UID2,Test",
            "Email,test@example.com,EUID,Test",
            "Phone,+01010101010,UID2,Test",
            "Phone,+01010101010,EUID,Test"
    })
    void testGenerateTokenForOptOutUser(IdentityType type, String identity, IdentityScope scope) {
        final UserIdentity userIdentity = createUserIdentity(identity, scope, type);

        final IdentityRequest identityRequestForceGenerate = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                userIdentity,
                OptoutCheckPolicy.DoNotRespect,
                IdentityEnvironment.Test);

        final IdentityRequest identityRequestRespectOptOut = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                userIdentity,
                OptoutCheckPolicy.RespectOptOut,
                IdentityEnvironment.Test);

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                .thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));

        final IdentityTokens tokens;
        final AdvertisingToken advertisingToken;
        final IdentityTokens tokensAfterOptOut;
        if (scope == IdentityScope.UID2) {
            tokens = uid2Service.generateIdentity(
                    identityRequestForceGenerate,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            advertisingToken = validateAndGetToken(tokenEncoder, tokens.getAdvertisingToken(), IdentityScope.UID2, userIdentity.identityType, identityRequestRespectOptOut.publisherIdentity.siteId);
            reset(shutdownHandler);
            tokensAfterOptOut = uid2Service.generateIdentity(
                    identityRequestRespectOptOut,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));

        } else {
            tokens = euidService.generateIdentity(
                    identityRequestForceGenerate,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            advertisingToken = validateAndGetToken(tokenEncoder, tokens.getAdvertisingToken(), IdentityScope.EUID, userIdentity.identityType, identityRequestRespectOptOut.publisherIdentity.siteId);
            reset(shutdownHandler);
            tokensAfterOptOut = euidService.generateIdentity(
                    identityRequestRespectOptOut,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokens);
        assertNotNull(advertisingToken.userIdentity);
        assertNotNull(tokensAfterOptOut);
        assertTrue(tokensAfterOptOut.getAdvertisingToken() == null || tokensAfterOptOut.getAdvertisingToken().isEmpty());

    }

    @ParameterizedTest
    @CsvSource({"Email,test@example.com,UID2,Test",
            "Email,test@example.com,EUID,Test",
            "Phone,+01010101010,UID2,Test",
            "Phone,+01010101010,EUID,Test"})
    void testIdentityMapForOptOutUser(IdentityType type, String identity, IdentityScope scope) {
        final UserIdentity userIdentity = createUserIdentity(identity, scope, type);
        final Instant now = Instant.now();

        final MapRequest mapRequestForceMap = new MapRequest(
                userIdentity,
                IdentityEnvironment.Test,
                OptoutCheckPolicy.DoNotRespect,
                now);

        final MapRequest mapRequestRespectOptOut = new MapRequest(
                userIdentity,
                IdentityEnvironment.Test,
                OptoutCheckPolicy.RespectOptOut,
                now);

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                .thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));

        final MappedIdentity mappedIdentity;
        final MappedIdentity mappedIdentityShouldBeOptOut;
        if (scope == IdentityScope.UID2) {
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            mappedIdentity = uid2Service.mapIdentity(mapRequestForceMap);
            reset(shutdownHandler);
            mappedIdentityShouldBeOptOut = uid2Service.mapIdentity(mapRequestRespectOptOut);
        } else {
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            mappedIdentity = euidService.mapIdentity(mapRequestForceMap);
            reset(shutdownHandler);
            mappedIdentityShouldBeOptOut = euidService.mapIdentity(mapRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(mappedIdentity);
        assertFalse(mappedIdentity.isOptedOut());
        assertNotNull(mappedIdentityShouldBeOptOut);
        assertTrue(mappedIdentityShouldBeOptOut.isOptedOut());
    }

    private enum TestIdentityInputType {
        Email(0),
        Phone(1),
        EmailHash(2),
        PhoneHash(3);

        public final int type;

        TestIdentityInputType(int type) { this.type = type; }
    }

    private InputUtil.InputVal generateInputVal(TestIdentityInputType type, String id) {
        InputUtil.InputVal inputVal;
        switch(type) {
            case Email:
                inputVal = InputUtil.normalizeEmail(id);
                break;
            case Phone:
                inputVal = InputUtil.normalizePhone(id);
                break;
            case EmailHash:
                inputVal = InputUtil.normalizeEmailHash(EncodingUtils.getSha256(id));
                break;
            default: //PhoneHash
                inputVal = InputUtil.normalizePhoneHash(EncodingUtils.getSha256(id));
        }
        return inputVal;
    }


    //UID2-1224
    @ParameterizedTest
    @CsvSource({"Email,optout@example.com,UID2",
            "EmailHash,optout@example.com,UID2",
            "Email,optout@example.com,EUID",
            "EmailHash,optout@example.com,EUID",
            "Phone,+00000000000,UID2",
            "PhoneHash,+00000000000,UID2",
            "Phone,+00000000000,EUID",
            "PhoneHash,+00000000000,EUID"})
    void testSpecialIdentityOptOutTokenGenerate(TestIdentityInputType type, String id, IdentityScope scope) {
        InputUtil.InputVal inputVal = generateInputVal(type, id);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toUserIdentity(scope,0, this.now),
                OptoutCheckPolicy.RespectOptOut,
                IdentityEnvironment.Test
        );

        // identity has no optout record, ensure generate still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        IdentityTokens tokens;
        if(scope == IdentityScope.EUID) {
            tokens = euidService.generateIdentity(
                    identityRequest,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        }
        else {
            tokens = uid2Service.generateIdentity(
                    identityRequest,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertEquals(tokens, IdentityTokens.LogoutToken);
    }

    @ParameterizedTest
    @CsvSource({"Email,optout@example.com,UID2",
            "EmailHash,optout@example.com,UID2",
            "Email,optout@example.com,EUID",
            "EmailHash,optout@example.com,EUID",
            "Phone,+00000000000,UID2",
            "PhoneHash,+00000000000,UID2",
            "Phone,+00000000000,EUID",
            "PhoneHash,+00000000000,EUID"})
    void testSpecialIdentityOptOutIdentityMap(TestIdentityInputType type, String id, IdentityScope scope) {
        InputUtil.InputVal inputVal = generateInputVal(type, id);

        final MapRequest mapRequestRespectOptOut = new MapRequest(
                inputVal.toUserIdentity(scope,0, this.now),
                IdentityEnvironment.Test,
                OptoutCheckPolicy.RespectOptOut,
                now);

        // identity has no optout record, ensure map still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final MappedIdentity mappedIdentity;
        if(scope == IdentityScope.EUID) {
            mappedIdentity = euidService.mapIdentity(mapRequestRespectOptOut);
        }
        else {
            mappedIdentity = uid2Service.mapIdentity(mapRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(mappedIdentity);
        assertTrue(mappedIdentity.isOptedOut());
    }

    @ParameterizedTest
    @CsvSource({"Email,optout@example.com,UID2",
            "EmailHash,optout@example.com,UID2",
            "Email,optout@example.com,EUID",
            "EmailHash,optout@example.com,EUID",
            "Phone,+00000000000,UID2",
            "PhoneHash,+00000000000,UID2",
            "Phone,+00000000000,EUID",
            "PhoneHash,+00000000000,EUID"})
    void testSpecialIdentityOptOutTokenRefresh(TestIdentityInputType type, String id, IdentityScope scope) {
        InputUtil.InputVal inputVal = generateInputVal(type, id);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toUserIdentity(scope,0, this.now),
                OptoutCheckPolicy.DoNotRespect,
                IdentityEnvironment.Test
        );

        IdentityTokens tokens;
        if(scope == IdentityScope.EUID) {
            tokens = euidService.generateIdentity(
                    identityRequest,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        }
        else {
            tokens = uid2Service.generateIdentity(
                    identityRequest,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokens);
        assertNotEquals(IdentityTokens.LogoutToken, tokens);

        // identity has no optout record, ensure refresh still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        reset(shutdownHandler);
        assertEquals(RefreshResponse.Optout, (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(
                refreshToken,
                Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS),
                IdentityEnvironment.Test));
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(anyBoolean());
    }

    @ParameterizedTest
    @CsvSource({"Email,refresh-optout@example.com,UID2",
            "EmailHash,refresh-optout@example.com,UID2",
            "Email,refresh-optout@example.com,EUID",
            "EmailHash,refresh-optout@example.com,EUID",
            "Phone,+00000000002,UID2",
            "PhoneHash,+00000000002,UID2",
            "Phone,+00000000002,EUID",
            "PhoneHash,+00000000002,EUID"})
    void testSpecialIdentityRefreshOptOutGenerate(TestIdentityInputType type, String id, IdentityScope scope) {
        InputUtil.InputVal inputVal = generateInputVal(type, id);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toUserIdentity(scope,0, this.now),
                OptoutCheckPolicy.RespectOptOut,
                IdentityEnvironment.Test
        );

        // identity has optout record, ensure still generates
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        IdentityTokens tokens;
        if(scope == IdentityScope.EUID) {
            tokens = euidService.generateIdentity(
                    identityRequest,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        }
        else {
            tokens = uid2Service.generateIdentity(
                    identityRequest,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokens);
        assertNotEquals(IdentityTokens.LogoutToken, tokens);

        // identity has no optout record, ensure refresh still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        reset(shutdownHandler);
        assertEquals(RefreshResponse.Optout, (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(
                refreshToken,
                Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS),
                IdentityEnvironment.Test));
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(anyBoolean());
    }

    @ParameterizedTest
    @CsvSource({"Email,refresh-optout@example.com,UID2",
            "EmailHash,refresh-optout@example.com,UID2",
            "Email,refresh-optout@example.com,EUID",
            "EmailHash,refresh-optout@example.com,EUID",
            "Phone,+00000000002,UID2",
            "PhoneHash,+00000000002,UID2",
            "Phone,+00000000002,EUID",
            "PhoneHash,+00000000002,EUID"})
    void testSpecialIdentityRefreshOptOutIdentityMap(TestIdentityInputType type, String id, IdentityScope scope) {
        InputUtil.InputVal inputVal = generateInputVal(type, id);

        final MapRequest mapRequestRespectOptOut = new MapRequest(
                inputVal.toUserIdentity(scope, 0, this.now),
                IdentityEnvironment.Test,
                OptoutCheckPolicy.RespectOptOut,
                now);

        // all identities have optout records, ensure refresh-optout identities still map
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        final MappedIdentity mappedIdentity;
        if(scope == IdentityScope.EUID) {
            mappedIdentity = euidService.mapIdentity(mapRequestRespectOptOut);
        }
        else {
            mappedIdentity = uid2Service.mapIdentity(mapRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(mappedIdentity);
        assertFalse(mappedIdentity.isOptedOut());
    }

    @ParameterizedTest
    @CsvSource({"Email,validate@example.com,UID2",
            "EmailHash,validate@example.com,UID2",
            "Email,validate@example.com,EUID",
            "EmailHash,validate@example.com,EUID",
            "Phone,+12345678901,UID2",
            "PhoneHash,+12345678901,UID2",
            "Phone,+12345678901,EUID",
            "PhoneHash,+12345678901,EUID"})
    void testSpecialIdentityValidateGenerate(TestIdentityInputType type, String id, IdentityScope scope) {
        InputUtil.InputVal inputVal = generateInputVal(type, id);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toUserIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut,
                IdentityEnvironment.Test
        );

        // all identities have optout records, ensure validate identities still get generated
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        IdentityTokens tokens;
        AdvertisingToken advertisingToken;
        if (scope == IdentityScope.EUID) {
            tokens = euidService.generateIdentity(
                    identityRequest,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        }
        else {
            tokens = uid2Service.generateIdentity(
                    identityRequest,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        }
        advertisingToken = validateAndGetToken(tokenEncoder, tokens.getAdvertisingToken(), scope, identityRequest.userIdentity.identityType, identityRequest.publisherIdentity.siteId);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokens);
        assertNotEquals(IdentityTokens.LogoutToken, tokens);
        assertNotNull(advertisingToken.userIdentity);
    }


    @ParameterizedTest
    @CsvSource({"Email,validate@example.com,UID2",
            "EmailHash,validate@example.com,UID2",
            "Email,validate@example.com,EUID",
            "EmailHash,validate@example.com,EUID",
            "Phone,+12345678901,UID2",
            "PhoneHash,+12345678901,UID2",
            "Phone,+12345678901,EUID",
            "PhoneHash,+12345678901,EUID"})
    void testSpecialIdentityValidateIdentityMap(TestIdentityInputType type, String id, IdentityScope scope) {
        InputUtil.InputVal inputVal = generateInputVal(type, id);

        final MapRequest mapRequestRespectOptOut = new MapRequest(
                inputVal.toUserIdentity(scope,0, this.now),
                IdentityEnvironment.Test,
                OptoutCheckPolicy.RespectOptOut,
                now);

        // all identities have optout records, ensure validate identities still get mapped
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        final MappedIdentity mappedIdentity;
        if(scope == IdentityScope.EUID) {
            mappedIdentity = euidService.mapIdentity(mapRequestRespectOptOut);
        }
        else {
            mappedIdentity = uid2Service.mapIdentity(mapRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(mappedIdentity);
        assertFalse(mappedIdentity.isOptedOut());
    }

    @ParameterizedTest
    @CsvSource({"Email,blah@unifiedid.com,UID2",
            "EmailHash,blah@unifiedid.com,UID2",
            "Phone,+61401234567,EUID",
            "PhoneHash,+61401234567,EUID",
            "Email,blah@unifiedid.com,EUID",
            "EmailHash,blah@unifiedid.com,EUID"})
    void testNormalIdentityOptIn(TestIdentityInputType type, String id, IdentityScope scope) {
        InputUtil.InputVal inputVal = generateInputVal(type, id);
        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toUserIdentity(scope,0, this.now),
                OptoutCheckPolicy.DoNotRespect,
                IdentityEnvironment.Test
        );
        IdentityTokens tokens;
        if(scope == IdentityScope.EUID) {
            tokens = euidService.generateIdentity(
                    identityRequest,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        }
        else {
            tokens = uid2Service.generateIdentity(
                    identityRequest,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotEquals(tokens, IdentityTokens.LogoutToken);
        assertNotNull(tokens);

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        RefreshResponse refreshResponse = (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(
                refreshToken,
                Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS),
                IdentityEnvironment.Test);
        assertTrue(refreshResponse.isRefreshed());
        assertNotNull(refreshResponse.getTokens());
        assertNotEquals(RefreshResponse.Optout, refreshResponse);
    }

    @ParameterizedTest
    @CsvSource({
            "Email,blah@unifiedid.com,UID2",
            "EmailHash,blah@unifiedid.com,UID2",
            "Phone,+61401234567,EUID",
            "PhoneHash,+61401234567,EUID",
            "Email,blah@unifiedid.com,EUID",
            "EmailHash,blah@unifiedid.com,EUID"
    })
    void testExpiredSaltsNotifiesShutdownHandler(TestIdentityInputType type, String id, IdentityScope scope) throws Exception {
        RotatingSaltProvider saltProvider = new RotatingSaltProvider(
                new EmbeddedResourceStorage(Main.class),
                "/com.uid2.core/test/salts/metadataExpired.json");
        saltProvider.loadContent();

        UIDOperatorService uid2Service = new UIDOperatorService(
                optOutStore,
                saltProvider,
                tokenEncoder,
                this.clock,
                IdentityScope.UID2,
                this.shutdownHandler::handleSaltRetrievalResponse,
                uid2Config.getBoolean(IdentityV3Prop),
                uidInstanceIdProvider
        );

        UIDOperatorService euidService = new UIDOperatorService(
                optOutStore,
                saltProvider,
                tokenEncoder,
                this.clock,
                IdentityScope.EUID,
                this.shutdownHandler::handleSaltRetrievalResponse,
                euidConfig.getBoolean(IdentityV3Prop),
                uidInstanceIdProvider
        );

        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        InputUtil.InputVal inputVal = generateInputVal(type, id);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toUserIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut,
                IdentityEnvironment.Test);

        IdentityTokens tokens;
        AdvertisingToken advertisingToken;
        reset(shutdownHandler);
        if (scope == IdentityScope.EUID) {
            tokens = euidService.generateIdentity(
                    identityRequest,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
            advertisingToken = validateAndGetToken(tokenEncoder, tokens.getAdvertisingToken(), IdentityScope.EUID, identityRequest.userIdentity.identityType, identityRequest.publisherIdentity.siteId);
        } else {
            tokens = uid2Service.generateIdentity(
                    identityRequest,
                    Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                    Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                    Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS));
            advertisingToken = validateAndGetToken(tokenEncoder, tokens.getAdvertisingToken(), IdentityScope.UID2, identityRequest.userIdentity.identityType, identityRequest.publisherIdentity.siteId);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(false);
        assertNotNull(tokens);
        assertNotEquals(IdentityTokens.LogoutToken, tokens);
        assertNotNull(advertisingToken.userIdentity);

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        reset(shutdownHandler);
        RefreshResponse refreshResponse = (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(
                refreshToken,
                Duration.ofSeconds(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                Duration.ofSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS),
                IdentityEnvironment.Test);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(false);
        assertTrue(refreshResponse.isRefreshed());
        assertNotNull(refreshResponse.getTokens());
        assertNotEquals(RefreshResponse.Optout, refreshResponse);

        final MapRequest mapRequest = new MapRequest(
                inputVal.toUserIdentity(scope,0, this.now),
                IdentityEnvironment.Test,
                OptoutCheckPolicy.RespectOptOut,
                now
        );
        final MappedIdentity mappedIdentity;
        reset(shutdownHandler);
        if (scope == IdentityScope.EUID) {
            mappedIdentity = euidService.mapIdentity(mapRequest);
        } else {
            mappedIdentity = uid2Service.mapIdentity(mapRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(false);
        assertNotNull(mappedIdentity);
        assertFalse(mappedIdentity.isOptedOut());

    }

    @Test
    void testMappedIdentityWithPreviousSaltReturnsPreviousUid() {
        var saltSnapshot = setUpMockSalts();

        long lastUpdated = this.now.minus(90, DAYS).plusMillis(1).toEpochMilli(); // 1 millis before 90 days old
        long refreshFrom = lastUpdated + Duration.ofDays(120).toMillis();

        SaltEntry salt = new SaltEntry(1, "1", lastUpdated, "salt", refreshFrom, "previousSalt", null, null);
        when(saltSnapshot.getRotatingSalt(any())).thenReturn(salt);

        var email = "test@uid.com";
        InputUtil.InputVal emailInput = generateInputVal(TestIdentityInputType.Email, email);
        MapRequest mapRequest = new MapRequest(emailInput.toUserIdentity(IdentityScope.UID2, 0, this.now), IdentityEnvironment.Test, OptoutCheckPolicy.RespectOptOut, now);

        MappedIdentity mappedIdentity = uid2Service.mapIdentity(mapRequest);

        var expectedCurrentUID = UIDOperatorVerticleTest.getRawUid(IdentityType.Email, email, FIRST_LEVEL_SALT, salt.currentSalt(), IdentityScope.UID2, uid2Config.getBoolean(IdentityV3Prop));
        var expectedPreviousUID = UIDOperatorVerticleTest.getRawUid(IdentityType.Email, email, FIRST_LEVEL_SALT, salt.previousSalt(), IdentityScope.UID2, uid2Config.getBoolean(IdentityV3Prop));
        assertArrayEquals(expectedCurrentUID, mappedIdentity.advertisingId);
        assertArrayEquals(expectedPreviousUID, mappedIdentity.previousAdvertisingId);
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "1"})
    void testMappedIdentityWithOutdatedPreviousSaltReturnsNoPreviousUid(long extraMsAfter90DaysOld) {
        var saltSnapshot = setUpMockSalts();

        long lastUpdated = this.now.minus(90, DAYS).minusMillis(extraMsAfter90DaysOld).toEpochMilli();
        long refreshFrom = lastUpdated + Duration.ofDays(120).toMillis();

        SaltEntry salt = new SaltEntry(1, "1", lastUpdated, "salt", refreshFrom, "previousSalt", null, null);
        when(saltSnapshot.getRotatingSalt(any())).thenReturn(salt);

        var email = "test@uid.com";
        InputUtil.InputVal emailInput = generateInputVal(TestIdentityInputType.Email, email);
        MapRequest mapRequest = new MapRequest(emailInput.toUserIdentity(IdentityScope.UID2, 0, this.now), IdentityEnvironment.Test, OptoutCheckPolicy.RespectOptOut, now);

        MappedIdentity mappedIdentity = uid2Service.mapIdentity(mapRequest);
        var expectedCurrentUID = UIDOperatorVerticleTest.getRawUid(IdentityType.Email, email, FIRST_LEVEL_SALT, salt.currentSalt(), IdentityScope.UID2, uid2Config.getBoolean(IdentityV3Prop));
        assertArrayEquals(expectedCurrentUID, mappedIdentity.advertisingId);
        assertArrayEquals(null , mappedIdentity.previousAdvertisingId);
    }

    @Test
    void testMappedIdentityWithNoPreviousSaltReturnsNoPreviousUid() {
        var saltSnapshot = setUpMockSalts();

        long lastUpdated = this.now.toEpochMilli();
        long refreshFrom = this.now.plus(30, DAYS).toEpochMilli();

        SaltEntry salt = new SaltEntry(1, "1", lastUpdated, "salt", refreshFrom, null, null, null);
        when(saltSnapshot.getRotatingSalt(any())).thenReturn(salt);

        var email = "test@uid.com";
        InputUtil.InputVal emailInput = generateInputVal(TestIdentityInputType.Email, email);
        MapRequest mapRequest = new MapRequest(emailInput.toUserIdentity(IdentityScope.UID2, 0, this.now), IdentityEnvironment.Test, OptoutCheckPolicy.RespectOptOut, now);

        MappedIdentity mappedIdentity = uid2Service.mapIdentity(mapRequest);

        var expectedCurrentUID = UIDOperatorVerticleTest.getRawUid(IdentityType.Email, email, FIRST_LEVEL_SALT, salt.currentSalt(), IdentityScope.UID2, uid2Config.getBoolean(IdentityV3Prop));
        assertArrayEquals(expectedCurrentUID, mappedIdentity.advertisingId);
        assertArrayEquals(null, mappedIdentity.previousAdvertisingId);
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "30"})
    void testMappedIdentityWithValidRefreshFrom(int refreshFromDays) {
        var saltSnapshot = setUpMockSalts();

        long lastUpdated = this.now.minus(30, DAYS).toEpochMilli();
        long refreshFrom = this.now.plus(refreshFromDays, DAYS).toEpochMilli();

        SaltEntry salt = new SaltEntry(1, "1", lastUpdated, "salt", refreshFrom, null, null, null);
        when(saltSnapshot.getRotatingSalt(any())).thenReturn(salt);

        var email = "test@uid.com";
        InputUtil.InputVal emailInput = generateInputVal(TestIdentityInputType.Email, email);
        MapRequest mapRequest = new MapRequest(emailInput.toUserIdentity(IdentityScope.UID2, 0, this.now), IdentityEnvironment.Test, OptoutCheckPolicy.RespectOptOut, now);

        MappedIdentity mappedIdentity = uid2Service.mapIdentity(mapRequest);

        assertEquals(refreshFrom, mappedIdentity.refreshFrom);
    }

    @Test
    void testMappedIdentityWithOutdatedRefreshFrom() {
        var saltSnapshot = setUpMockSalts();

        long lastUpdated = this.now.minus(31, DAYS).toEpochMilli();
        long outdatedRefreshFrom = this.now.minus(1, DAYS).toEpochMilli();

        SaltEntry salt = new SaltEntry(1, "1", lastUpdated, "salt", outdatedRefreshFrom, null, null, null);
        when(saltSnapshot.getRotatingSalt(any())).thenReturn(salt);

        var email = "test@uid.com";
        InputUtil.InputVal emailInput = generateInputVal(TestIdentityInputType.Email, email);
        MapRequest mapRequest = new MapRequest(emailInput.toUserIdentity(IdentityScope.UID2, 0, this.now), IdentityEnvironment.Test, OptoutCheckPolicy.RespectOptOut, now);

        MappedIdentity mappedIdentity = uid2Service.mapIdentity(mapRequest);

        long expectedRefreshFrom = this.now.truncatedTo(DAYS).plus(1, DAYS).toEpochMilli();
        assertEquals(expectedRefreshFrom, mappedIdentity.refreshFrom);
    }
}
