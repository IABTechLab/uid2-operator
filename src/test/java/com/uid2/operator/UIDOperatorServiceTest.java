package com.uid2.operator;

import com.uid2.operator.model.*;
import com.uid2.operator.model.identities.FirstLevelHash;
import com.uid2.operator.model.identities.HashedDii;
import com.uid2.operator.model.identities.RawUid;
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

    private HashedDii createHashedDiiIdentity(String rawIdentityHash, IdentityScope scope, IdentityType type) {
        return new HashedDii(
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

    private void assertIdentityScopeIdentityType(IdentityScope expectedScope, IdentityType expectedIdentityType,
                                                 HashedDii hashedDii) {
        assertEquals(expectedScope, hashedDii.identityScope());
        assertEquals(expectedIdentityType, hashedDii.identityType());
    }

    private void assertIdentityScopeIdentityType(IdentityScope expectedScope, IdentityType expectedIdentityType,
                                                 RawUid rawUid) {
        assertEquals(expectedScope, rawUid.identityScope());
        assertEquals(expectedIdentityType, rawUid.identityType());
    }

    private void assertIdentityScopeIdentityType(IdentityScope expectedScope, IdentityType expectedIdentityType,
                                                 FirstLevelHash firstLevelHash) {
        assertEquals(expectedScope, firstLevelHash.identityScope());
        assertEquals(expectedIdentityType, firstLevelHash.identityType());
    }





    @ParameterizedTest
    @CsvSource({"123, V2","127, V4","128, V4"}) //site id 127 and 128 is for testing "site_ids_using_v4_tokens"
    public void testGenerateAndRefresh(int siteId, TokenVersion tokenVersion) {
        IdentityScope expectedIdentityScope = IdentityScope.UID2;
        IdentityType expectedIdentityType = IdentityType.Email;


        final TokenGenerateRequest tokenGenerateRequest = new TokenGenerateRequest(
                new SourcePublisher(siteId, 124, 125),
                createHashedDiiIdentity("test-email-hash", expectedIdentityScope, expectedIdentityType),
                OptoutCheckPolicy.DoNotRespect, PrivacyBits.fromInt(0),
                this.now.minusSeconds(234)
        );
        final TokenGenerateResponse tokenGenerateResponse = uid2Service.generateIdentity(tokenGenerateRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokenGenerateResponse);

        UIDOperatorVerticleTest.validateAdvertisingToken(tokenGenerateResponse.getAdvertisingToken(), tokenVersion, IdentityScope.UID2, IdentityType.Email);
        AdvertisingTokenRequest advertisingTokenRequest = tokenEncoder.decodeAdvertisingToken(tokenGenerateResponse.getAdvertisingToken());
        assertEquals(this.now.plusSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS), advertisingTokenRequest.expiresAt);
        assertEquals(tokenGenerateRequest.sourcePublisher.siteId, advertisingTokenRequest.sourcePublisher.siteId);
        assertIdentityScopeIdentityType(expectedIdentityScope, expectedIdentityType,
                advertisingTokenRequest.rawUid);
        assertEquals(tokenGenerateRequest.establishedAt, advertisingTokenRequest.establishedAt);
        assertEquals(tokenGenerateRequest.privacyBits, advertisingTokenRequest.privacyBits);

        TokenRefreshRequest tokenRefreshRequest = tokenEncoder.decodeRefreshToken(tokenGenerateResponse.getRefreshToken());
        assertEquals(this.now, tokenRefreshRequest.createdAt);
        assertEquals(this.now.plusSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS), tokenRefreshRequest.expiresAt);
        assertEquals(tokenGenerateRequest.sourcePublisher.siteId, tokenRefreshRequest.sourcePublisher.siteId);
        assertIdentityScopeIdentityType(expectedIdentityScope, expectedIdentityType, tokenRefreshRequest.firstLevelHash);
        assertEquals(tokenGenerateRequest.establishedAt, tokenRefreshRequest.firstLevelHash.establishedAt());

        final byte[] firstLevelHash = getFirstLevelHash(tokenGenerateRequest.hashedDii.hashedDii(),
                saltProvider.getSnapshot(this.now).getFirstLevelSalt() );
        assertArrayEquals(firstLevelHash, tokenRefreshRequest.firstLevelHash.firstLevelHash());


        setNow(Instant.now().plusSeconds(200));

        reset(shutdownHandler);
        final TokenRefreshResponse refreshResponse = uid2Service.refreshIdentity(tokenRefreshRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(refreshResponse);
        assertEquals(TokenRefreshResponse.Status.Refreshed, refreshResponse.getStatus());
        assertNotNull(refreshResponse.getIdentityResponse());

        UIDOperatorVerticleTest.validateAdvertisingToken(refreshResponse.getIdentityResponse().getAdvertisingToken(), tokenVersion, IdentityScope.UID2, IdentityType.Email);
        AdvertisingTokenRequest advertisingTokenRequest2 = tokenEncoder.decodeAdvertisingToken(refreshResponse.getIdentityResponse().getAdvertisingToken());
        assertEquals(this.now.plusSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS), advertisingTokenRequest2.expiresAt);
        assertEquals(advertisingTokenRequest.sourcePublisher.siteId, advertisingTokenRequest2.sourcePublisher.siteId);
        assertIdentityScopeIdentityType(expectedIdentityScope, expectedIdentityType,
                advertisingTokenRequest2.rawUid);
        assertEquals(advertisingTokenRequest.establishedAt, advertisingTokenRequest2.establishedAt);
        assertArrayEquals(advertisingTokenRequest.rawUid.rawUid(),
                advertisingTokenRequest2.rawUid.rawUid());
        assertEquals(tokenGenerateRequest.privacyBits, advertisingTokenRequest2.privacyBits);

        TokenRefreshRequest tokenRefreshRequest2 = tokenEncoder.decodeRefreshToken(refreshResponse.getIdentityResponse().getRefreshToken());
        assertEquals(this.now, tokenRefreshRequest2.createdAt);
        assertEquals(this.now.plusSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS), tokenRefreshRequest2.expiresAt);
        assertEquals(tokenRefreshRequest.sourcePublisher.siteId, tokenRefreshRequest2.sourcePublisher.siteId);
        assertIdentityScopeIdentityType(expectedIdentityScope, expectedIdentityType, tokenRefreshRequest2.firstLevelHash);
        assertEquals(tokenRefreshRequest.firstLevelHash.establishedAt(), tokenRefreshRequest2.firstLevelHash.establishedAt());
        assertArrayEquals(tokenRefreshRequest.firstLevelHash.firstLevelHash(), tokenRefreshRequest2.firstLevelHash.firstLevelHash());
        assertArrayEquals(firstLevelHash, tokenRefreshRequest2.firstLevelHash.firstLevelHash());
    }

    @Test
    public void testTestOptOutKey_DoNotRespectOptout() {
        final InputUtil.InputVal inputVal = InputUtil.normalizeEmail(IdentityConst.OptOutIdentityForEmail);

        final TokenGenerateRequest tokenGenerateRequest = new TokenGenerateRequest(
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(IdentityScope.UID2),
                OptoutCheckPolicy.DoNotRespect, PrivacyBits.fromInt(0), this.now
        );
        final TokenGenerateResponse tokenGenerateResponse = uid2Service.generateIdentity(tokenGenerateRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokenGenerateResponse);
        assertFalse(tokenGenerateResponse.isOptedOut());

        final TokenRefreshRequest tokenRefreshRequest = this.tokenEncoder.decodeRefreshToken(tokenGenerateResponse.getRefreshToken());
        assertEquals(TokenRefreshResponse.Optout, uid2Service.refreshIdentity(tokenRefreshRequest));
    }

    @Test
    public void testTestOptOutKey_RespectOptout() {
        final InputUtil.InputVal inputVal = InputUtil.normalizeEmail(IdentityConst.OptOutIdentityForEmail);

        final TokenGenerateRequest tokenGenerateRequest = new TokenGenerateRequest(
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(IdentityScope.UID2),
                OptoutCheckPolicy.RespectOptOut, PrivacyBits.fromInt(0), this.now
        );
        final TokenGenerateResponse tokenGenerateResponse = uid2Service.generateIdentity(tokenGenerateRequest);
        assertTrue(tokenGenerateResponse.isOptedOut());
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
    }

    @Test
    public void testTestOptOutKeyIdentityScopeMismatch() {
        final String email = "optout@example.com";
        final InputUtil.InputVal inputVal = InputUtil.normalizeEmail(email);

        final TokenGenerateRequest tokenGenerateRequest = new TokenGenerateRequest(
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(IdentityScope.EUID),
                OptoutCheckPolicy.DoNotRespect, PrivacyBits.fromInt(0), this.now
        );
        final TokenGenerateResponse tokenGenerateResponse = euidService.generateIdentity(tokenGenerateRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokenGenerateResponse);

        final TokenRefreshRequest tokenRefreshRequest = this.tokenEncoder.decodeRefreshToken(tokenGenerateResponse.getRefreshToken());
        reset(shutdownHandler);
        assertEquals(TokenRefreshResponse.Invalid, uid2Service.refreshIdentity(tokenRefreshRequest));
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(anyBoolean());
    }

    @ParameterizedTest
    @CsvSource({"Email,test@example.com,UID2",
            "Email,test@example.com,EUID",
            "Phone,+01010101010,UID2",
            "Phone,+01010101010,EUID"})
    public void testGenerateTokenForOptOutUser(IdentityType type, String id, IdentityScope scope) {
        final HashedDii hashedDii = createHashedDiiIdentity(TokenUtils.getIdentityHashString(id),
                scope, type);

        final TokenGenerateRequest tokenGenerateRequestForceGenerate = new TokenGenerateRequest(
                new SourcePublisher(123, 124, 125),
                hashedDii,
                OptoutCheckPolicy.DoNotRespect, PrivacyBits.fromInt(0),
                this.now.minusSeconds(234));

        final TokenGenerateRequest tokenGenerateRequestRespectOptOut = new TokenGenerateRequest(
                new SourcePublisher(123, 124, 125),
                hashedDii,
                OptoutCheckPolicy.RespectOptOut, PrivacyBits.fromInt(0),
                this.now.minusSeconds(234));

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(FirstLevelHash.class)))
                .thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));

        final TokenGenerateResponse tokenGenerateResponse;
        final AdvertisingTokenRequest advertisingTokenRequest;
        final TokenGenerateResponse tokenGenerateResponseAfterOptOut;
        if (scope == IdentityScope.UID2) {
            tokenGenerateResponse = uid2Service.generateIdentity(tokenGenerateRequestForceGenerate);
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            advertisingTokenRequest = validateAndGetToken(tokenEncoder, tokenGenerateResponse.getAdvertisingToken(), IdentityScope.UID2, hashedDii.identityType(), tokenGenerateRequestRespectOptOut.sourcePublisher.siteId);
            reset(shutdownHandler);
            tokenGenerateResponseAfterOptOut = uid2Service.generateIdentity(tokenGenerateRequestRespectOptOut);

        } else {
            tokenGenerateResponse = euidService.generateIdentity(tokenGenerateRequestForceGenerate);
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            advertisingTokenRequest = validateAndGetToken(tokenEncoder, tokenGenerateResponse.getAdvertisingToken(), IdentityScope.EUID, hashedDii.identityType(), tokenGenerateRequestRespectOptOut.sourcePublisher.siteId);
            reset(shutdownHandler);
            tokenGenerateResponseAfterOptOut = euidService.generateIdentity(tokenGenerateRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokenGenerateResponse);
        assertNotNull(advertisingTokenRequest.rawUid);
        assertNotNull(tokenGenerateResponseAfterOptOut);
        assertTrue(tokenGenerateResponseAfterOptOut.getAdvertisingToken() == null || tokenGenerateResponseAfterOptOut.getAdvertisingToken().isEmpty());
        assertTrue(tokenGenerateResponseAfterOptOut.isOptedOut());
    }

    @ParameterizedTest
    @CsvSource({"Email,test@example.com,UID2",
            "Email,test@example.com,EUID",
            "Phone,+01010101010,UID2",
            "Phone,+01010101010,EUID"})
    public void testIdentityMapForOptOutUser(IdentityType type, String identity, IdentityScope scope) {
        final HashedDii hashedDii = createHashedDiiIdentity(identity, scope, type);
        final Instant now = Instant.now();

        final IdentityMapRequestItem mapRequestForceIdentityMapItem = new IdentityMapRequestItem(
                hashedDii,
                OptoutCheckPolicy.DoNotRespect,
                now);

        final IdentityMapRequestItem identityMapRequestItemRespectOptOut = new IdentityMapRequestItem(
                hashedDii,
                OptoutCheckPolicy.RespectOptOut,
                now);

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(FirstLevelHash.class)))
                .thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));

        final IdentityMapResponseItem identityMapResponseItem;
        final IdentityMapResponseItem identityMapResponseItemShouldBeOptOut;
        if (scope == IdentityScope.UID2) {
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            identityMapResponseItem = uid2Service.mapHashedDii(mapRequestForceIdentityMapItem);
            reset(shutdownHandler);
            identityMapResponseItemShouldBeOptOut = uid2Service.mapHashedDii(identityMapRequestItemRespectOptOut);
        } else {
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            identityMapResponseItem = euidService.mapHashedDii(mapRequestForceIdentityMapItem);
            reset(shutdownHandler);
            identityMapResponseItemShouldBeOptOut = euidService.mapHashedDii(identityMapRequestItemRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identityMapResponseItem);
        assertFalse(identityMapResponseItem.isOptedOut());
        assertNotNull(identityMapResponseItemShouldBeOptOut);
        assertTrue(identityMapResponseItemShouldBeOptOut.isOptedOut());
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

        final TokenGenerateRequest tokenGenerateRequest = new TokenGenerateRequest(
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut, PrivacyBits.fromInt(0), this.now
        );

        // identity has no optout record, ensure generate still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        TokenGenerateResponse tokenGenerateResponse;
        if(scope == IdentityScope.EUID) {
            tokenGenerateResponse = euidService.generateIdentity(tokenGenerateRequest);
        }
        else {
            tokenGenerateResponse = uid2Service.generateIdentity(tokenGenerateRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertEquals(tokenGenerateResponse, TokenGenerateResponse.OptOutResponse);
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

        final IdentityMapRequestItem identityMapRequestItemRespectOptOut = new IdentityMapRequestItem(
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut,
                now);

        // identity has no optout record, ensure map still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final IdentityMapResponseItem identityMapResponseItem;
        if(scope == IdentityScope.EUID) {
            identityMapResponseItem = euidService.mapHashedDii(identityMapRequestItemRespectOptOut);
        }
        else {
            identityMapResponseItem = uid2Service.mapHashedDii(identityMapRequestItemRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identityMapResponseItem);
        assertTrue(identityMapResponseItem.isOptedOut());
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

        final TokenGenerateRequest tokenGenerateRequest = new TokenGenerateRequest(
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.DoNotRespect, PrivacyBits.fromInt(0), this.now
        );

        TokenGenerateResponse tokenGenerateResponse;
        if(scope == IdentityScope.EUID) {
            tokenGenerateResponse = euidService.generateIdentity(tokenGenerateRequest);
        }
        else {
            tokenGenerateResponse = uid2Service.generateIdentity(tokenGenerateRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokenGenerateResponse);
        assertNotEquals(TokenGenerateResponse.OptOutResponse, tokenGenerateResponse);

        // identity has no optout record, ensure refresh still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final TokenRefreshRequest tokenRefreshRequest = this.tokenEncoder.decodeRefreshToken(tokenGenerateResponse.getRefreshToken());
        reset(shutdownHandler);
        assertEquals(TokenRefreshResponse.Optout, (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(tokenRefreshRequest));
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

        final TokenGenerateRequest tokenGenerateRequest = new TokenGenerateRequest(
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut, PrivacyBits.fromInt(0), this.now
        );

        // identity has optout record, ensure still generates
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        TokenGenerateResponse tokenGenerateResponse;
        if(scope == IdentityScope.EUID) {
            tokenGenerateResponse = euidService.generateIdentity(tokenGenerateRequest);
        }
        else {
            tokenGenerateResponse = uid2Service.generateIdentity(tokenGenerateRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokenGenerateResponse);
        assertNotEquals(TokenGenerateResponse.OptOutResponse, tokenGenerateResponse);

        // identity has no optout record, ensure refresh still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final TokenRefreshRequest tokenRefreshRequest = this.tokenEncoder.decodeRefreshToken(tokenGenerateResponse.getRefreshToken());
        reset(shutdownHandler);
        assertEquals(TokenRefreshResponse.Optout, (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(tokenRefreshRequest));
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

        final IdentityMapRequestItem identityMapRequestItemRespectOptOut = new IdentityMapRequestItem(
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut,
                now);

        // all identities have optout records, ensure refresh-optout identities still map
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        final IdentityMapResponseItem identityMapResponseItem;
        if(scope == IdentityScope.EUID) {
            identityMapResponseItem = euidService.mapHashedDii(identityMapRequestItemRespectOptOut);
        }
        else {
            identityMapResponseItem = uid2Service.mapHashedDii(identityMapRequestItemRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identityMapResponseItem);
        assertFalse(identityMapResponseItem.isOptedOut());
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

        final TokenGenerateRequest tokenGenerateRequest = new TokenGenerateRequest(
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut, PrivacyBits.fromInt(0), this.now
        );

        // all identities have optout records, ensure validate identities still get generated
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        TokenGenerateResponse tokenGenerateResponse;
        AdvertisingTokenRequest advertisingTokenRequest;
        if (scope == IdentityScope.EUID) {
            tokenGenerateResponse = euidService.generateIdentity(tokenGenerateRequest);
        }
        else {
            tokenGenerateResponse = uid2Service.generateIdentity(tokenGenerateRequest);
        }
        advertisingTokenRequest = validateAndGetToken(tokenEncoder, tokenGenerateResponse.getAdvertisingToken(), scope, tokenGenerateRequest.hashedDii.identityType(), tokenGenerateRequest.sourcePublisher.siteId);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(tokenGenerateResponse);
        assertNotEquals(TokenGenerateResponse.OptOutResponse, tokenGenerateResponse);
        assertNotNull(advertisingTokenRequest.rawUid);
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

        final IdentityMapRequestItem identityMapRequestItemRespectOptOut = new IdentityMapRequestItem(
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut,
                now);

        // all identities have optout records, ensure validate identities still get mapped
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        final IdentityMapResponseItem identityMapResponseItem;
        if(scope == IdentityScope.EUID) {
            identityMapResponseItem = euidService.mapHashedDii(identityMapRequestItemRespectOptOut);
        }
        else {
            identityMapResponseItem = uid2Service.mapHashedDii(identityMapRequestItemRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identityMapResponseItem);
        assertFalse(identityMapResponseItem.isOptedOut());
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
        final TokenGenerateRequest tokenGenerateRequest = new TokenGenerateRequest(
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.DoNotRespect
        );
        TokenGenerateResponse tokenGenerateResponse;
        if(scope == IdentityScope.EUID) {
            tokenGenerateResponse = euidService.generateIdentity(tokenGenerateRequest);
        }
        else {
            tokenGenerateResponse = uid2Service.generateIdentity(tokenGenerateRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotEquals(tokenGenerateResponse, TokenGenerateResponse.OptOutResponse);
        assertNotNull(tokenGenerateResponse);

        final TokenRefreshRequest tokenRefreshRequest = this.tokenEncoder.decodeRefreshToken(tokenGenerateResponse.getRefreshToken());
        TokenRefreshResponse refreshResponse = (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(tokenRefreshRequest);
        assertTrue(refreshResponse.isRefreshed());
        assertNotNull(refreshResponse.getIdentityResponse());
        assertNotEquals(TokenRefreshResponse.Optout, refreshResponse);
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

        final TokenGenerateRequest tokenGenerateRequest = new TokenGenerateRequest(
                new SourcePublisher(123, 124, 125),
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut, PrivacyBits.fromInt(0), this.now);

        TokenGenerateResponse tokenGenerateResponse;
        AdvertisingTokenRequest advertisingTokenRequest;
        reset(shutdownHandler);
        if(scope == IdentityScope.EUID) {
            tokenGenerateResponse = euidService.generateIdentity(tokenGenerateRequest);
            advertisingTokenRequest = validateAndGetToken(tokenEncoder, tokenGenerateResponse.getAdvertisingToken(), IdentityScope.EUID, tokenGenerateRequest.hashedDii.identityType(), tokenGenerateRequest.sourcePublisher.siteId);
        }
        else {
            tokenGenerateResponse = uid2Service.generateIdentity(tokenGenerateRequest);
            advertisingTokenRequest = validateAndGetToken(tokenEncoder, tokenGenerateResponse.getAdvertisingToken(), IdentityScope.UID2, tokenGenerateRequest.hashedDii.identityType(), tokenGenerateRequest.sourcePublisher.siteId);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(false);
        assertNotNull(tokenGenerateResponse);
        assertNotEquals(TokenGenerateResponse.OptOutResponse, tokenGenerateResponse);
        assertNotNull(advertisingTokenRequest.rawUid);

        final TokenRefreshRequest tokenRefreshRequest = this.tokenEncoder.decodeRefreshToken(tokenGenerateResponse.getRefreshToken());
        reset(shutdownHandler);
        TokenRefreshResponse refreshResponse = (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(tokenRefreshRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(false);
        assertTrue(refreshResponse.isRefreshed());
        assertNotNull(refreshResponse.getIdentityResponse());
        assertNotEquals(TokenRefreshResponse.Optout, refreshResponse);

        final IdentityMapRequestItem identityMapRequestItem = new IdentityMapRequestItem(
                inputVal.toHashedDiiIdentity(scope),
                OptoutCheckPolicy.RespectOptOut,
                now);
        final IdentityMapResponseItem identityMapResponseItem;
        reset(shutdownHandler);
        if(scope == IdentityScope.EUID) {
            identityMapResponseItem = euidService.mapHashedDii(identityMapRequestItem);
        }
        else {
            identityMapResponseItem = uid2Service.mapHashedDii(identityMapRequestItem);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(false);
        assertNotNull(identityMapResponseItem);
        assertFalse(identityMapResponseItem.isOptedOut());

    }
}
