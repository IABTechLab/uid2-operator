package com.uid2.operator;

import com.uid2.operator.model.*;
import com.uid2.operator.service.EncodingUtils;
import com.uid2.operator.service.EncryptedTokenEncoder;
import com.uid2.operator.service.InputUtil;
import com.uid2.operator.service.UIDOperatorService;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.operator.vertx.OperatorShutdownHandler;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.RotatingSaltProvider;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.store.reader.RotatingKeysetKeyStore;
import com.uid2.shared.store.reader.RotatingKeysetProvider;
import com.uid2.shared.store.scope.GlobalScope;
import com.uid2.shared.model.TokenVersion;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class UIDOperatorServiceTest {
    private AutoCloseable mocks;
    @Mock private IOptOutStore optOutStore;
    @Mock private Clock clock;
    @Mock private OperatorShutdownHandler shutdownHandler;
    EncryptedTokenEncoder tokenEncoder;
    JsonObject uid2Config;
    JsonObject euidConfig;
    UIDOperatorService uid2Service;
    UIDOperatorService euidService;
    Instant now;

    final int IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS = 600;
    final int REFRESH_TOKEN_EXPIRES_AFTER_SECONDS = 900;
    final int REFRESH_IDENTITY_TOKEN_AFTER_SECONDS = 300;

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
        uid2Config.put("advertising_token_v4_percentage", 0);
        uid2Config.put("advertising_token_v3", false); // prod is using v2 token version for now
        uid2Config.put("identity_v3", false);

        uid2Service = new UIDOperatorService(
                uid2Config,
                optOutStore,
                saltProvider,
                tokenEncoder,
                this.clock,
                IdentityScope.UID2,
                this.shutdownHandler::handleSaltRetrievalResponse
        );

        euidConfig = new JsonObject();
        euidConfig.put(UIDOperatorService.IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
        euidConfig.put(UIDOperatorService.REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, REFRESH_TOKEN_EXPIRES_AFTER_SECONDS);
        euidConfig.put(UIDOperatorService.REFRESH_IDENTITY_TOKEN_AFTER_SECONDS, REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
        euidConfig.put("advertising_token_v4_percentage", 0);
        euidConfig.put("advertising_token_v3", true);
        euidConfig.put("identity_v3", true);

        euidService = new UIDOperatorService(
                euidConfig,
                optOutStore,
                saltProvider,
                tokenEncoder,
                this.clock,
                IdentityScope.EUID,
                this.shutdownHandler::handleSaltRetrievalResponse
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

    private AdvertisingToken validateAndGetToken(EncryptedTokenEncoder tokenEncoder, String advertisingTokenString, IdentityScope scope, IdentityType type) {
        TokenVersion tokenVersion = (scope == IdentityScope.UID2) ? uid2Service.getAdvertisingTokenVersionForTests() : euidService.getAdvertisingTokenVersionForTests();
        UIDOperatorVerticleTest.validateAdvertisingToken(advertisingTokenString, tokenVersion, scope, type);
        return tokenEncoder.decodeAdvertisingToken(advertisingTokenString);
    }

    @Test
    public void testGenerateAndRefresh() {
        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                createUserIdentity("test-email-hash", IdentityScope.UID2, IdentityType.Email),
                OptoutCheckPolicy.DoNotRespect
        );
        final IdentityTokens tokens = uid2Service.generateIdentity(identityRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokens);

        AdvertisingToken advertisingToken = validateAndGetToken(tokenEncoder, tokens.getAdvertisingToken(), IdentityScope.UID2, IdentityType.Email);
        assertEquals(this.now.plusSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS), advertisingToken.expiresAt);
        assertEquals(identityRequest.publisherIdentity.siteId, advertisingToken.publisherIdentity.siteId);
        assertEquals(identityRequest.userIdentity.identityScope, advertisingToken.userIdentity.identityScope);
        assertEquals(identityRequest.userIdentity.identityType, advertisingToken.userIdentity.identityType);
        assertEquals(identityRequest.userIdentity.establishedAt, advertisingToken.userIdentity.establishedAt);

        RefreshToken refreshToken = tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        assertEquals(this.now, refreshToken.createdAt);
        assertEquals(this.now.plusSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS), refreshToken.expiresAt);
        assertEquals(identityRequest.publisherIdentity.siteId, refreshToken.publisherIdentity.siteId);
        assertEquals(identityRequest.userIdentity.identityScope, refreshToken.userIdentity.identityScope);
        assertEquals(identityRequest.userIdentity.identityType, refreshToken.userIdentity.identityType);
        assertEquals(identityRequest.userIdentity.establishedAt, refreshToken.userIdentity.establishedAt);

        setNow(Instant.now().plusSeconds(200));

        reset(shutdownHandler);
        final RefreshResponse refreshResponse = uid2Service.refreshIdentity(refreshToken);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(refreshResponse);
        assertEquals(RefreshResponse.Status.Refreshed, refreshResponse.getStatus());
        assertNotNull(refreshResponse.getTokens());

        AdvertisingToken advertisingToken2 = validateAndGetToken(tokenEncoder, refreshResponse.getTokens().getAdvertisingToken(), IdentityScope.UID2, IdentityType.Email);
        assertEquals(this.now.plusSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS), advertisingToken2.expiresAt);
        assertEquals(advertisingToken.publisherIdentity.siteId, advertisingToken2.publisherIdentity.siteId);
        assertEquals(advertisingToken.userIdentity.identityScope, advertisingToken2.userIdentity.identityScope);
        assertEquals(advertisingToken.userIdentity.identityType, advertisingToken2.userIdentity.identityType);
        assertEquals(advertisingToken.userIdentity.establishedAt, advertisingToken2.userIdentity.establishedAt);
        assertArrayEquals(advertisingToken.userIdentity.id, advertisingToken2.userIdentity.id);

        RefreshToken refreshToken2 = tokenEncoder.decodeRefreshToken(refreshResponse.getTokens().getRefreshToken());
        assertEquals(this.now, refreshToken2.createdAt);
        assertEquals(this.now.plusSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS), refreshToken2.expiresAt);
        assertEquals(refreshToken.publisherIdentity.siteId, refreshToken2.publisherIdentity.siteId);
        assertEquals(refreshToken.userIdentity.identityScope, refreshToken2.userIdentity.identityScope);
        assertEquals(refreshToken.userIdentity.identityType, refreshToken2.userIdentity.identityType);
        assertEquals(refreshToken.userIdentity.establishedAt, refreshToken2.userIdentity.establishedAt);
        assertArrayEquals(refreshToken.userIdentity.id, refreshToken2.userIdentity.id);
    }

    @Test
    public void testTestOptOutKey() {
        final InputUtil.InputVal inputVal = InputUtil.normalizeEmail(IdentityConst.OptOutIdentityForEmail);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toUserIdentity(IdentityScope.UID2, 0, this.now),
                OptoutCheckPolicy.DoNotRespect
        );
        final IdentityTokens tokens = uid2Service.generateIdentity(identityRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokens);

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        assertEquals(RefreshResponse.Optout, uid2Service.refreshIdentity(refreshToken));
    }

    @Test
    public void testTestOptOutKeyIdentityScopeMismatch() {
        final String email = "optout@example.com";
        final InputUtil.InputVal inputVal = InputUtil.normalizeEmail(email);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toUserIdentity(IdentityScope.EUID, 0, this.now),
                OptoutCheckPolicy.DoNotRespect
        );
        final IdentityTokens tokens = euidService.generateIdentity(identityRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokens);

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        reset(shutdownHandler);
        assertEquals(RefreshResponse.Invalid, uid2Service.refreshIdentity(refreshToken));
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(anyBoolean());
    }

    @ParameterizedTest
    @CsvSource({"Email,test@example.com,UID2",
            "Email,test@example.com,EUID",
            "Phone,+01010101010,UID2",
            "Phone,+01010101010,EUID"})
    public void testGenerateTokenForOptOutUser(IdentityType type, String identity, IdentityScope scope) {
        final UserIdentity userIdentity = createUserIdentity(identity, scope, type);

        final IdentityRequest identityRequestForceGenerate = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                userIdentity,
                OptoutCheckPolicy.DoNotRespect);

        final IdentityRequest identityRequestRespectOptOut = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                userIdentity,
                OptoutCheckPolicy.RespectOptOut);

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(UserIdentity.class)))
                .thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));

        final IdentityTokens tokens;
        final AdvertisingToken advertisingToken;
        final IdentityTokens tokensAfterOptOut;
        if (scope == IdentityScope.UID2) {
            tokens = uid2Service.generateIdentity(identityRequestForceGenerate);
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            advertisingToken = validateAndGetToken(tokenEncoder, tokens.getAdvertisingToken(), IdentityScope.UID2, userIdentity.identityType);
            reset(shutdownHandler);
            tokensAfterOptOut = uid2Service.generateIdentity(identityRequestRespectOptOut);

        } else {
            tokens = euidService.generateIdentity(identityRequestForceGenerate);
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            advertisingToken = validateAndGetToken(tokenEncoder, tokens.getAdvertisingToken(), IdentityScope.EUID, userIdentity.identityType);
            reset(shutdownHandler);
            tokensAfterOptOut = euidService.generateIdentity(identityRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokens);
        assertNotNull(advertisingToken.userIdentity);
        assertNotNull(tokensAfterOptOut);
        assertTrue(tokensAfterOptOut.getAdvertisingToken() == null || tokensAfterOptOut.getAdvertisingToken().isEmpty());

    }

    @ParameterizedTest
    @CsvSource({"Email,test@example.com,UID2",
            "Email,test@example.com,EUID",
            "Phone,+01010101010,UID2",
            "Phone,+01010101010,EUID"})
    public void testIdentityMapForOptOutUser(IdentityType type, String identity, IdentityScope scope) {
        final UserIdentity userIdentity = createUserIdentity(identity, scope, type);
        final Instant now = Instant.now();

        final MapRequest mapRequestForceMap = new MapRequest(
                userIdentity,
                OptoutCheckPolicy.DoNotRespect,
                now);

        final MapRequest mapRequestRespectOptOut = new MapRequest(
                userIdentity,
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
                inputVal.toUserIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut
        );

        // identity has no optout record, ensure generate still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        IdentityTokens tokens;
        if(scope == IdentityScope.EUID) {
            tokens = euidService.generateIdentity(identityRequest);
        }
        else {
            tokens = uid2Service.generateIdentity(identityRequest);
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
                inputVal.toUserIdentity(scope, 0, this.now),
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
                inputVal.toUserIdentity(scope, 0, this.now),
                OptoutCheckPolicy.DoNotRespect
        );

        IdentityTokens tokens;
        if(scope == IdentityScope.EUID) {
            tokens = euidService.generateIdentity(identityRequest);
        }
        else {
            tokens = uid2Service.generateIdentity(identityRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokens);
        assertNotEquals(IdentityTokens.LogoutToken, tokens);

        // identity has no optout record, ensure refresh still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        reset(shutdownHandler);
        assertEquals(RefreshResponse.Optout, (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(refreshToken));
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
                inputVal.toUserIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut
        );

        // identity has optout record, ensure still generates
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        IdentityTokens tokens;
        if(scope == IdentityScope.EUID) {
            tokens = euidService.generateIdentity(identityRequest);
        }
        else {
            tokens = uid2Service.generateIdentity(identityRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokens);
        assertNotEquals(IdentityTokens.LogoutToken, tokens);

        // identity has no optout record, ensure refresh still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        reset(shutdownHandler);
        assertEquals(RefreshResponse.Optout, (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(refreshToken));
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
                OptoutCheckPolicy.RespectOptOut
        );

        // all identities have optout records, ensure validate identities still get generated
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        IdentityTokens tokens;
        AdvertisingToken advertisingToken;
        if(scope == IdentityScope.EUID) {
            tokens = euidService.generateIdentity(identityRequest);
            advertisingToken = validateAndGetToken(tokenEncoder, tokens.getAdvertisingToken(), scope, identityRequest.userIdentity.identityType);
        }
        else {
            tokens = uid2Service.generateIdentity(identityRequest);
            advertisingToken = validateAndGetToken(tokenEncoder, tokens.getAdvertisingToken(), scope, identityRequest.userIdentity.identityType);
        }
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
                inputVal.toUserIdentity(scope, 0, this.now),
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
                inputVal.toUserIdentity(scope, 0, this.now),
                OptoutCheckPolicy.DoNotRespect
        );
        IdentityTokens tokens;
        if(scope == IdentityScope.EUID) {
            tokens = euidService.generateIdentity(identityRequest);
        }
        else {
            tokens = uid2Service.generateIdentity(identityRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotEquals(tokens, IdentityTokens.LogoutToken);
        assertNotNull(tokens);

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        reset(shutdownHandler);
        RefreshResponse refreshResponse = (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(refreshToken);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertTrue(refreshResponse.isRefreshed());
        assertNotNull(refreshResponse.getTokens());
        assertNotEquals(RefreshResponse.Optout, refreshResponse);
    }

    @ParameterizedTest
    @CsvSource({"Email,blah@unifiedid.com,UID2",
            "EmailHash,blah@unifiedid.com,UID2",
            "Phone,+61401234567,EUID",
            "PhoneHash,+61401234567,EUID",
            "Email,blah@unifiedid.com,EUID",
            "EmailHash,blah@unifiedid.com,EUID"})
    void testExpiredSaltsNotifiesShutdownHandler(TestIdentityInputType type, String id, IdentityScope scope) throws Exception {
        RotatingSaltProvider saltProvider = new RotatingSaltProvider(
                new EmbeddedResourceStorage(Main.class),
                "/com.uid2.core/test/salts/metadataExpired.json");
        saltProvider.loadContent();

        UIDOperatorService uid2Service = new UIDOperatorService(
                uid2Config,
                optOutStore,
                saltProvider,
                tokenEncoder,
                this.clock,
                IdentityScope.UID2,
                this.shutdownHandler::handleSaltRetrievalResponse
        );

        UIDOperatorService euidService = new UIDOperatorService(
                euidConfig,
                optOutStore,
                saltProvider,
                tokenEncoder,
                this.clock,
                IdentityScope.EUID,
                this.shutdownHandler::handleSaltRetrievalResponse
        );

        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        InputUtil.InputVal inputVal = generateInputVal(type, id);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toUserIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut);

        IdentityTokens tokens;
        AdvertisingToken advertisingToken;
        reset(shutdownHandler);
        if(scope == IdentityScope.EUID) {
            tokens = euidService.generateIdentity(identityRequest);
            advertisingToken = validateAndGetToken(tokenEncoder, tokens.getAdvertisingToken(), IdentityScope.EUID, identityRequest.userIdentity.identityType);
        }
        else {
            tokens = uid2Service.generateIdentity(identityRequest);
            advertisingToken = validateAndGetToken(tokenEncoder, tokens.getAdvertisingToken(), IdentityScope.UID2, identityRequest.userIdentity.identityType);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(false);
        assertNotNull(tokens);
        assertNotEquals(IdentityTokens.LogoutToken, tokens);
        assertNotNull(advertisingToken.userIdentity);

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        reset(shutdownHandler);
        RefreshResponse refreshResponse = (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(refreshToken);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(false);
        assertTrue(refreshResponse.isRefreshed());
        assertNotNull(refreshResponse.getTokens());
        assertNotEquals(RefreshResponse.Optout, refreshResponse);

        final MapRequest mapRequest = new MapRequest(
                inputVal.toUserIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut,
                now);

        final MappedIdentity mappedIdentity;
        reset(shutdownHandler);
        if(scope == IdentityScope.EUID) {
            mappedIdentity = euidService.mapIdentity(mapRequest);
        }
        else {
            mappedIdentity = uid2Service.mapIdentity(mapRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(false);
        assertNotNull(mappedIdentity);
        assertFalse(mappedIdentity.isOptedOut());

    }
}
