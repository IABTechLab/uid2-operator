package com.uid2.operator;

import com.uid2.operator.model.*;
import com.uid2.operator.model.userIdentity.FirstLevelHashIdentity;
import com.uid2.operator.model.userIdentity.HashedDiiIdentity;
import com.uid2.operator.model.userIdentity.UserIdentity;
import com.uid2.operator.service.*;
import com.uid2.operator.service.EncodingUtils;
import com.uid2.operator.service.EncryptedTokenEncoder;
import com.uid2.operator.service.InputUtil;
import com.uid2.operator.service.UIDOperatorService;
import com.uid2.operator.store.IOptOutStore;
import com.uid2.operator.util.PrivacyBits;
import com.uid2.operator.vertx.OperatorShutdownHandler;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.ISaltProvider;
import com.uid2.shared.store.RotatingSaltProvider;
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

import static com.uid2.operator.service.TokenUtils.getFirstLevelHash;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.time.Clock;
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
    ExtendedUIDOperatorService uid2Service;
    ExtendedUIDOperatorService euidService;
    Instant now;
    RotatingSaltProvider saltProvider;
    final int IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS = 600;
    final int REFRESH_TOKEN_EXPIRES_AFTER_SECONDS = 900;
    final int REFRESH_IDENTITY_TOKEN_AFTER_SECONDS = 300;

    class ExtendedUIDOperatorService extends UIDOperatorService {
        public ExtendedUIDOperatorService(JsonObject config, IOptOutStore optOutStore, ISaltProvider saltProvider, EncryptedTokenEncoder encoder, Clock clock, IdentityScope identityScope, Handler<Boolean> saltRetrievalResponseHandler) {
            super(config, optOutStore, saltProvider, encoder, clock, identityScope, saltRetrievalResponseHandler);
        }

        public TokenVersion getAdvertisingTokenVersionForTests(int siteId) {
            assert this.advertisingTokenV4Percentage == 0 || this.advertisingTokenV4Percentage == 100; //we want tests to be deterministic
            if (this.siteIdsUsingV4Tokens.contains(siteId)) {
                return TokenVersion.V4;
            }
            return this.advertisingTokenV4Percentage == 100 ? TokenVersion.V4 : this.tokenVersionToUseIfNotV4;
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

        saltProvider = new RotatingSaltProvider(
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
        uid2Config.put("site_ids_using_v4_tokens", "127,128");
        uid2Config.put("advertising_token_v3", false); // prod is using v2 token version for now
        uid2Config.put("identity_v3", false);

        uid2Service = new ExtendedUIDOperatorService(
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

        euidService = new ExtendedUIDOperatorService(
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

    private HashedDiiIdentity createHashedDiiIdentity(String rawIdentityHash, IdentityScope scope, IdentityType type) {
        return new HashedDiiIdentity(
                scope,
                type,
                rawIdentityHash.getBytes(StandardCharsets.UTF_8)
        );
    }

    private AdvertisingTokenRequest validateAndGetToken(EncryptedTokenEncoder tokenEncoder, String advertisingTokenString, IdentityScope scope, IdentityType type, int siteId) {
        TokenVersion tokenVersion = (scope == IdentityScope.UID2) ? uid2Service.getAdvertisingTokenVersionForTests(siteId) : euidService.getAdvertisingTokenVersionForTests(siteId);
        UIDOperatorVerticleTest.validateAdvertisingToken(advertisingTokenString, tokenVersion, scope, type);
        return tokenEncoder.decodeAdvertisingToken(advertisingTokenString);
    }

    private void assertIdentityScopeIdentityType(UserIdentity expctedValues,
                                                 UserIdentity actualValues) {
        assertEquals(expctedValues.identityScope, actualValues.identityScope);
        assertEquals(expctedValues.identityType, actualValues.identityType);
    }

    @ParameterizedTest
    @CsvSource({"123, V2","127, V4","128, V4"}) //site id 127 and 128 is for testing "site_ids_using_v4_tokens"
    public void testGenerateAndRefresh(int siteId, TokenVersion tokenVersion) {
        final IdentityRequest identityRequest = new IdentityRequest(
                new SourcePublisher(siteId, 124, 125),
                createHashedDiiIdentity("test-email-hash", IdentityScope.UID2, IdentityType.Email),
                OptoutCheckPolicy.DoNotRespect, PrivacyBits.fromInt(0),
                this.now.minusSeconds(234)
        );
        final IdentityResponse identityResponse = uid2Service.generateIdentity(identityRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identityResponse);

        UIDOperatorVerticleTest.validateAdvertisingToken(identityResponse.getAdvertisingToken(), tokenVersion, IdentityScope.UID2, IdentityType.Email);
        AdvertisingTokenRequest advertisingTokenRequest = tokenEncoder.decodeAdvertisingToken(identityResponse.getAdvertisingToken());
        assertEquals(this.now.plusSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS), advertisingTokenRequest.expiresAt);
        assertEquals(identityRequest.sourcePublisher.siteId, advertisingTokenRequest.sourcePublisher.siteId);
        assertIdentityScopeIdentityType(identityRequest.hashedDiiIdentity, advertisingTokenRequest.rawUidIdentity);
        assertEquals(identityRequest.establishedAt, advertisingTokenRequest.establishedAt);
        assertEquals(identityRequest.privacyBits, advertisingTokenRequest.privacyBits);

        RefreshTokenRequest refreshTokenRequest = tokenEncoder.decodeRefreshToken(identityResponse.getRefreshToken());
        assertEquals(this.now, refreshTokenRequest.createdAt);
        assertEquals(this.now.plusSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS), refreshTokenRequest.expiresAt);
        assertEquals(identityRequest.sourcePublisher.siteId, refreshTokenRequest.sourcePublisher.siteId);
        assertIdentityScopeIdentityType(identityRequest.hashedDiiIdentity, refreshTokenRequest.firstLevelHashIdentity);
        assertEquals(identityRequest.establishedAt, refreshTokenRequest.firstLevelHashIdentity.establishedAt);

        final byte[] firstLevelHash = getFirstLevelHash(identityRequest.hashedDiiIdentity.hashedDii,
                saltProvider.getSnapshot(this.now).getFirstLevelSalt() );
        assertArrayEquals(firstLevelHash, refreshTokenRequest.firstLevelHashIdentity.firstLevelHash);


        setNow(Instant.now().plusSeconds(200));

        reset(shutdownHandler);
        final RefreshResponse refreshResponse = uid2Service.refreshIdentity(refreshTokenRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(refreshResponse);
        assertEquals(RefreshResponse.Status.Refreshed, refreshResponse.getStatus());
        assertNotNull(refreshResponse.getIdentityResponse());

        UIDOperatorVerticleTest.validateAdvertisingToken(refreshResponse.getIdentityResponse().getAdvertisingToken(), tokenVersion, IdentityScope.UID2, IdentityType.Email);
        AdvertisingTokenRequest advertisingTokenRequest2 = tokenEncoder.decodeAdvertisingToken(refreshResponse.getIdentityResponse().getAdvertisingToken());
        assertEquals(this.now.plusSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS), advertisingTokenRequest2.expiresAt);
        assertEquals(advertisingTokenRequest.sourcePublisher.siteId, advertisingTokenRequest2.sourcePublisher.siteId);
        assertIdentityScopeIdentityType(advertisingTokenRequest.rawUidIdentity,
                advertisingTokenRequest2.rawUidIdentity);
        assertEquals(advertisingTokenRequest.establishedAt, advertisingTokenRequest2.establishedAt);
        assertArrayEquals(advertisingTokenRequest.rawUidIdentity.rawUid,
                advertisingTokenRequest2.rawUidIdentity.rawUid);
        assertEquals(identityRequest.privacyBits, advertisingTokenRequest2.privacyBits);

        RefreshTokenRequest refreshTokenRequest2 = tokenEncoder.decodeRefreshToken(refreshResponse.getIdentityResponse().getRefreshToken());
        assertEquals(this.now, refreshTokenRequest2.createdAt);
        assertEquals(this.now.plusSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS), refreshTokenRequest2.expiresAt);
        assertEquals(refreshTokenRequest.sourcePublisher.siteId, refreshTokenRequest2.sourcePublisher.siteId);
        assertIdentityScopeIdentityType(refreshTokenRequest.firstLevelHashIdentity, refreshTokenRequest2.firstLevelHashIdentity);
        assertEquals(refreshTokenRequest.firstLevelHashIdentity.establishedAt, refreshTokenRequest2.firstLevelHashIdentity.establishedAt);
        assertArrayEquals(refreshTokenRequest.firstLevelHashIdentity.firstLevelHash, refreshTokenRequest2.firstLevelHashIdentity.firstLevelHash);
        assertArrayEquals(firstLevelHash, refreshTokenRequest2.firstLevelHashIdentity.firstLevelHash);
    }

    @Test
    public void testTestOptOutKey_DoNotRespectOptout() {
        final InputUtil.InputVal inputVal = InputUtil.normalizeEmail(IdentityConst.OptOutIdentityForEmail);

        final IdentityRequest identityRequest = new IdentityRequest(
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(IdentityScope.UID2),
                OptoutCheckPolicy.DoNotRespect, PrivacyBits.fromInt(0), this.now
        );
        final IdentityResponse identityResponse = uid2Service.generateIdentity(identityRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identityResponse);
        assertFalse(identityResponse.isOptedOut());

        final RefreshTokenRequest refreshTokenRequest = this.tokenEncoder.decodeRefreshToken(identityResponse.getRefreshToken());
        assertEquals(RefreshResponse.Optout, uid2Service.refreshIdentity(refreshTokenRequest));
    }

    @Test
    public void testTestOptOutKey_RespectOptout() {
        final InputUtil.InputVal inputVal = InputUtil.normalizeEmail(IdentityConst.OptOutIdentityForEmail);

        final IdentityRequest identityRequest = new IdentityRequest(
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(IdentityScope.UID2),
                OptoutCheckPolicy.RespectOptOut, PrivacyBits.fromInt(0), this.now
        );
        final IdentityResponse identityResponse = uid2Service.generateIdentity(identityRequest);
        assertTrue(identityResponse.isOptedOut());
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
    }

    @Test
    public void testTestOptOutKeyIdentityScopeMismatch() {
        final String email = "optout@example.com";
        final InputUtil.InputVal inputVal = InputUtil.normalizeEmail(email);

        final IdentityRequest identityRequest = new IdentityRequest(
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(IdentityScope.EUID),
                OptoutCheckPolicy.DoNotRespect, PrivacyBits.fromInt(0), this.now
        );
        final IdentityResponse identityResponse = euidService.generateIdentity(identityRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identityResponse);

        final RefreshTokenRequest refreshTokenRequest = this.tokenEncoder.decodeRefreshToken(identityResponse.getRefreshToken());
        reset(shutdownHandler);
        assertEquals(RefreshResponse.Invalid, uid2Service.refreshIdentity(refreshTokenRequest));
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(anyBoolean());
    }

    @ParameterizedTest
    @CsvSource({"Email,test@example.com,UID2",
            "Email,test@example.com,EUID",
            "Phone,+01010101010,UID2",
            "Phone,+01010101010,EUID"})
    public void testGenerateTokenForOptOutUser(IdentityType type, String id, IdentityScope scope) {
        final HashedDiiIdentity hashedDiiIdentity = createHashedDiiIdentity(TokenUtils.getIdentityHashString(id),
                scope, type);

        final IdentityRequest identityRequestForceGenerate = new IdentityRequest(
                new SourcePublisher(123, 124, 125),
                hashedDiiIdentity,
                OptoutCheckPolicy.DoNotRespect, PrivacyBits.fromInt(0),
                this.now.minusSeconds(234));

        final IdentityRequest identityRequestRespectOptOut = new IdentityRequest(
                new SourcePublisher(123, 124, 125),
                hashedDiiIdentity,
                OptoutCheckPolicy.RespectOptOut, PrivacyBits.fromInt(0),
                this.now.minusSeconds(234));

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(FirstLevelHashIdentity.class)))
                .thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));

        final IdentityResponse identityResponse;
        final AdvertisingTokenRequest advertisingTokenRequest;
        final IdentityResponse identityResponseAfterOptOut;
        if (scope == IdentityScope.UID2) {
            identityResponse = uid2Service.generateIdentity(identityRequestForceGenerate);
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            advertisingTokenRequest = validateAndGetToken(tokenEncoder, identityResponse.getAdvertisingToken(), IdentityScope.UID2, hashedDiiIdentity.identityType, identityRequestRespectOptOut.sourcePublisher.siteId);
            reset(shutdownHandler);
            identityResponseAfterOptOut = uid2Service.generateIdentity(identityRequestRespectOptOut);

        } else {
            identityResponse = euidService.generateIdentity(identityRequestForceGenerate);
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            advertisingTokenRequest = validateAndGetToken(tokenEncoder, identityResponse.getAdvertisingToken(), IdentityScope.EUID, hashedDiiIdentity.identityType, identityRequestRespectOptOut.sourcePublisher.siteId);
            reset(shutdownHandler);
            identityResponseAfterOptOut = euidService.generateIdentity(identityRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identityResponse);
        assertNotNull(advertisingTokenRequest.rawUidIdentity);
        assertNotNull(identityResponseAfterOptOut);
        assertTrue(identityResponseAfterOptOut.getAdvertisingToken() == null || identityResponseAfterOptOut.getAdvertisingToken().isEmpty());
        assertTrue(identityResponseAfterOptOut.isOptedOut());
    }

    @ParameterizedTest
    @CsvSource({"Email,test@example.com,UID2",
            "Email,test@example.com,EUID",
            "Phone,+01010101010,UID2",
            "Phone,+01010101010,EUID"})
    public void testIdentityMapForOptOutUser(IdentityType type, String identity, IdentityScope scope) {
        final HashedDiiIdentity hashedDiiIdentity = createHashedDiiIdentity(identity, scope, type);
        final Instant now = Instant.now();

        final MapRequest mapRequestForceMap = new MapRequest(
                hashedDiiIdentity,
                OptoutCheckPolicy.DoNotRespect,
                now);

        final MapRequest mapRequestRespectOptOut = new MapRequest(
                hashedDiiIdentity,
                OptoutCheckPolicy.RespectOptOut,
                now);

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(FirstLevelHashIdentity.class)))
                .thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));

        final RawUidResponse rawUidResponse;
        final RawUidResponse rawUidResponseShouldBeOptOut;
        if (scope == IdentityScope.UID2) {
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            rawUidResponse = uid2Service.mapHashedDiiIdentity(mapRequestForceMap);
            reset(shutdownHandler);
            rawUidResponseShouldBeOptOut = uid2Service.mapHashedDiiIdentity(mapRequestRespectOptOut);
        } else {
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            rawUidResponse = euidService.mapHashedDiiIdentity(mapRequestForceMap);
            reset(shutdownHandler);
            rawUidResponseShouldBeOptOut = euidService.mapHashedDiiIdentity(mapRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(rawUidResponse);
        assertFalse(rawUidResponse.isOptedOut());
        assertNotNull(rawUidResponseShouldBeOptOut);
        assertTrue(rawUidResponseShouldBeOptOut.isOptedOut());
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
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut, PrivacyBits.fromInt(0), this.now
        );

        // identity has no optout record, ensure generate still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        IdentityResponse identityResponse;
        if(scope == IdentityScope.EUID) {
            identityResponse = euidService.generateIdentity(identityRequest);
        }
        else {
            identityResponse = uid2Service.generateIdentity(identityRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertEquals(identityResponse, IdentityResponse.OptOutIdentityResponse);
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
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut,
                now);

        // identity has no optout record, ensure map still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final RawUidResponse rawUidResponse;
        if(scope == IdentityScope.EUID) {
            rawUidResponse = euidService.mapHashedDiiIdentity(mapRequestRespectOptOut);
        }
        else {
            rawUidResponse = uid2Service.mapHashedDiiIdentity(mapRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(rawUidResponse);
        assertTrue(rawUidResponse.isOptedOut());
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
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.DoNotRespect, PrivacyBits.fromInt(0), this.now
        );

        IdentityResponse identityResponse;
        if(scope == IdentityScope.EUID) {
            identityResponse = euidService.generateIdentity(identityRequest);
        }
        else {
            identityResponse = uid2Service.generateIdentity(identityRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identityResponse);
        assertNotEquals(IdentityResponse.OptOutIdentityResponse, identityResponse);

        // identity has no optout record, ensure refresh still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final RefreshTokenRequest refreshTokenRequest = this.tokenEncoder.decodeRefreshToken(identityResponse.getRefreshToken());
        reset(shutdownHandler);
        assertEquals(RefreshResponse.Optout, (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(refreshTokenRequest));
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
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut, PrivacyBits.fromInt(0), this.now
        );

        // identity has optout record, ensure still generates
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        IdentityResponse identityResponse;
        if(scope == IdentityScope.EUID) {
            identityResponse = euidService.generateIdentity(identityRequest);
        }
        else {
            identityResponse = uid2Service.generateIdentity(identityRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identityResponse);
        assertNotEquals(IdentityResponse.OptOutIdentityResponse, identityResponse);

        // identity has no optout record, ensure refresh still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final RefreshTokenRequest refreshTokenRequest = this.tokenEncoder.decodeRefreshToken(identityResponse.getRefreshToken());
        reset(shutdownHandler);
        assertEquals(RefreshResponse.Optout, (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(refreshTokenRequest));
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
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut,
                now);

        // all identities have optout records, ensure refresh-optout identities still map
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        final RawUidResponse rawUidResponse;
        if(scope == IdentityScope.EUID) {
            rawUidResponse = euidService.mapHashedDiiIdentity(mapRequestRespectOptOut);
        }
        else {
            rawUidResponse = uid2Service.mapHashedDiiIdentity(mapRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(rawUidResponse);
        assertFalse(rawUidResponse.isOptedOut());
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
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut, PrivacyBits.fromInt(0), this.now
        );

        // all identities have optout records, ensure validate identities still get generated
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        IdentityResponse identityResponse;
        AdvertisingTokenRequest advertisingTokenRequest;
        if (scope == IdentityScope.EUID) {
            identityResponse = euidService.generateIdentity(identityRequest);
        }
        else {
            identityResponse = uid2Service.generateIdentity(identityRequest);
        }
        advertisingTokenRequest = validateAndGetToken(tokenEncoder, identityResponse.getAdvertisingToken(), scope, identityRequest.hashedDiiIdentity.identityType, identityRequest.sourcePublisher.siteId);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identityResponse);
        assertNotEquals(IdentityResponse.OptOutIdentityResponse, identityResponse);
        assertNotNull(advertisingTokenRequest.rawUidIdentity);
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
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut,
                now);

        // all identities have optout records, ensure validate identities still get mapped
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        final RawUidResponse rawUidResponse;
        if(scope == IdentityScope.EUID) {
            rawUidResponse = euidService.mapHashedDiiIdentity(mapRequestRespectOptOut);
        }
        else {
            rawUidResponse = uid2Service.mapHashedDiiIdentity(mapRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(rawUidResponse);
        assertFalse(rawUidResponse.isOptedOut());
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
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.DoNotRespect
        );
        IdentityResponse identityResponse;
        if(scope == IdentityScope.EUID) {
            identityResponse = euidService.generateIdentity(identityRequest);
        }
        else {
            identityResponse = uid2Service.generateIdentity(identityRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotEquals(identityResponse, IdentityResponse.OptOutIdentityResponse);
        assertNotNull(identityResponse);

        final RefreshTokenRequest refreshTokenRequest = this.tokenEncoder.decodeRefreshToken(identityResponse.getRefreshToken());
        RefreshResponse refreshResponse = (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(refreshTokenRequest);
        assertTrue(refreshResponse.isRefreshed());
        assertNotNull(refreshResponse.getIdentityResponse());
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
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut, PrivacyBits.fromInt(0), this.now);

        IdentityResponse identityResponse;
        AdvertisingTokenRequest advertisingTokenRequest;
        reset(shutdownHandler);
        if(scope == IdentityScope.EUID) {
            identityResponse = euidService.generateIdentity(identityRequest);
            advertisingTokenRequest = validateAndGetToken(tokenEncoder, identityResponse.getAdvertisingToken(), IdentityScope.EUID, identityRequest.hashedDiiIdentity.identityType, identityRequest.sourcePublisher.siteId);
        }
        else {
            identityResponse = uid2Service.generateIdentity(identityRequest);
            advertisingTokenRequest = validateAndGetToken(tokenEncoder, identityResponse.getAdvertisingToken(), IdentityScope.UID2, identityRequest.hashedDiiIdentity.identityType, identityRequest.sourcePublisher.siteId);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(false);
        assertNotNull(identityResponse);
        assertNotEquals(IdentityResponse.OptOutIdentityResponse, identityResponse);
        assertNotNull(advertisingTokenRequest.rawUidIdentity);

        final RefreshTokenRequest refreshTokenRequest = this.tokenEncoder.decodeRefreshToken(identityResponse.getRefreshToken());
        reset(shutdownHandler);
        RefreshResponse refreshResponse = (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(refreshTokenRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(false);
        assertTrue(refreshResponse.isRefreshed());
        assertNotNull(refreshResponse.getIdentityResponse());
        assertNotEquals(RefreshResponse.Optout, refreshResponse);

        final MapRequest mapRequest = new MapRequest(
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut,
                now);
        final RawUidResponse rawUidResponse;
        reset(shutdownHandler);
        if(scope == IdentityScope.EUID) {
            rawUidResponse = euidService.mapHashedDiiIdentity(mapRequest);
        }
        else {
            rawUidResponse = uid2Service.mapHashedDiiIdentity(mapRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(false);
        assertNotNull(rawUidResponse);
        assertFalse(rawUidResponse.isOptedOut());

    }
}
