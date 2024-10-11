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
        uid2Config.put("site_ids_using_v4_tokens", "127,128");
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

    private HashedDiiIdentity createHashedDiiIdentity(String rawIdentityHash, IdentityScope scope, IdentityType type) {
        return new HashedDiiIdentity(
                scope,
                type,
                rawIdentityHash.getBytes(StandardCharsets.UTF_8),
                0,
                this.now.minusSeconds(234),
                this.now.plusSeconds(12345)
        );
    }

    private AdvertisingTokenInput validateAndGetToken(EncryptedTokenEncoder tokenEncoder, String advertisingTokenString, IdentityScope scope, IdentityType type, int siteId) {
        TokenVersion tokenVersion = (scope == IdentityScope.UID2) ? uid2Service.getAdvertisingTokenVersionForTests(siteId) : euidService.getAdvertisingTokenVersionForTests(siteId);
        UIDOperatorVerticleTest.validateAdvertisingToken(advertisingTokenString, tokenVersion, scope, type);
        return tokenEncoder.decodeAdvertisingToken(advertisingTokenString);
    }

    private void assertIdentityScopeIdentityTypeAndEstablishedAt(UserIdentity expctedValues,
                                                                 UserIdentity actualValues) {
        assertEquals(expctedValues.GetIdentityScope(), actualValues.GetIdentityScope());
        assertEquals(expctedValues.GetIdentityType(), actualValues.GetIdentityType());
        assertEquals(expctedValues.GetEstablishedAt(), actualValues.GetEstablishedAt());
    }

    @ParameterizedTest
    @CsvSource({"123, V2","127, V4","128, V4"}) //site id 127 and 128 is for testing "site_ids_using_v4_tokens"
    public void testGenerateAndRefresh(int siteId, TokenVersion tokenVersion) {
        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(siteId, 124, 125),
                createHashedDiiIdentity("test-email-hash", IdentityScope.UID2, IdentityType.Email),
                OptoutCheckPolicy.DoNotRespect
        );
        final Identity identity = uid2Service.generateIdentity(identityRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identity);

        UIDOperatorVerticleTest.validateAdvertisingToken(identity.getAdvertisingToken(), tokenVersion, IdentityScope.UID2, IdentityType.Email);
        AdvertisingTokenInput advertisingTokenInput = tokenEncoder.decodeAdvertisingToken(identity.getAdvertisingToken());assertEquals(this.now.plusSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS), advertisingTokenInput.expiresAt);
        assertEquals(identityRequest.publisherIdentity.siteId, advertisingTokenInput.publisherIdentity.siteId);
        assertIdentityScopeIdentityTypeAndEstablishedAt(identityRequest.hashedDiiIdentity, advertisingTokenInput.rawUidIdentity);

        RefreshTokenInput refreshTokenInput = tokenEncoder.decodeRefreshToken(identity.getRefreshToken());
        assertEquals(this.now, refreshTokenInput.createdAt);
        assertEquals(this.now.plusSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS), refreshTokenInput.expiresAt);
        assertEquals(identityRequest.publisherIdentity.siteId, refreshTokenInput.publisherIdentity.siteId);
        assertIdentityScopeIdentityTypeAndEstablishedAt(identityRequest.hashedDiiIdentity, refreshTokenInput.firstLevelHashIdentity);

        setNow(Instant.now().plusSeconds(200));

        reset(shutdownHandler);
        final RefreshResponse refreshResponse = uid2Service.refreshIdentity(refreshTokenInput);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(refreshResponse);
        assertEquals(RefreshResponse.Status.Refreshed, refreshResponse.getStatus());
        assertNotNull(refreshResponse.getIdentity());

        UIDOperatorVerticleTest.validateAdvertisingToken(refreshResponse.getIdentity().getAdvertisingToken(), tokenVersion, IdentityScope.UID2, IdentityType.Email);
        AdvertisingTokenInput advertisingTokenInput2 = tokenEncoder.decodeAdvertisingToken(refreshResponse.getIdentity().getAdvertisingToken());
        assertEquals(this.now.plusSeconds(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS), advertisingTokenInput2.expiresAt);
        assertEquals(advertisingTokenInput.publisherIdentity.siteId, advertisingTokenInput2.publisherIdentity.siteId);
        assertIdentityScopeIdentityTypeAndEstablishedAt(advertisingTokenInput.rawUidIdentity,
                advertisingTokenInput2.rawUidIdentity);
        assertArrayEquals(advertisingTokenInput.rawUidIdentity.rawUid,
                advertisingTokenInput2.rawUidIdentity.rawUid);

        RefreshTokenInput refreshTokenInput2 = tokenEncoder.decodeRefreshToken(refreshResponse.getIdentity().getRefreshToken());
        assertEquals(this.now, refreshTokenInput2.createdAt);
        assertEquals(this.now.plusSeconds(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS), refreshTokenInput2.expiresAt);
        assertEquals(refreshTokenInput.publisherIdentity.siteId, refreshTokenInput2.publisherIdentity.siteId);
        assertIdentityScopeIdentityTypeAndEstablishedAt(refreshTokenInput.firstLevelHashIdentity, refreshTokenInput2.firstLevelHashIdentity);
        assertArrayEquals(refreshTokenInput.firstLevelHashIdentity.firstLevelHash, refreshTokenInput2.firstLevelHashIdentity.firstLevelHash);
    }

    @Test
    public void testTestOptOutKey_DoNotRespectOptout() {
        final InputUtil.InputVal inputVal = InputUtil.normalizeEmail(IdentityConst.OptOutIdentityForEmail);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toHashedDiiIdentity(IdentityScope.UID2, 0, this.now),
                OptoutCheckPolicy.DoNotRespect
        );
        final Identity identity = uid2Service.generateIdentity(identityRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identity);
        assertFalse(identity.isEmptyToken());

        final RefreshTokenInput refreshTokenInput = this.tokenEncoder.decodeRefreshToken(identity.getRefreshToken());
        assertEquals(RefreshResponse.Optout, uid2Service.refreshIdentity(refreshTokenInput));
    }

    @Test
    public void testTestOptOutKey_RespectOptout() {
        final InputUtil.InputVal inputVal = InputUtil.normalizeEmail(IdentityConst.OptOutIdentityForEmail);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toHashedDiiIdentity(IdentityScope.UID2, 0, this.now),
                OptoutCheckPolicy.RespectOptOut
        );
        final Identity identity = uid2Service.generateIdentity(identityRequest);
        assertTrue(identity.isEmptyToken());
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
    }

    @Test
    public void testTestOptOutKeyIdentityScopeMismatch() {
        final String email = "optout@example.com";
        final InputUtil.InputVal inputVal = InputUtil.normalizeEmail(email);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toHashedDiiIdentity(IdentityScope.EUID, 0, this.now),
                OptoutCheckPolicy.DoNotRespect
        );
        final Identity identity = euidService.generateIdentity(identityRequest);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identity);

        final RefreshTokenInput refreshTokenInput = this.tokenEncoder.decodeRefreshToken(identity.getRefreshToken());
        reset(shutdownHandler);
        assertEquals(RefreshResponse.Invalid, uid2Service.refreshIdentity(refreshTokenInput));
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(anyBoolean());
    }

    @ParameterizedTest
    @CsvSource({"Email,test@example.com,UID2",
            "Email,test@example.com,EUID",
            "Phone,+01010101010,UID2",
            "Phone,+01010101010,EUID"})
    public void testGenerateTokenForOptOutUser(IdentityType type, String id, IdentityScope scope) {
        final HashedDiiIdentity hashedDiiIdentity = createHashedDiiIdentity(id, scope, type);

        final IdentityRequest identityRequestForceGenerate = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                hashedDiiIdentity,
                OptoutCheckPolicy.DoNotRespect);

        final IdentityRequest identityRequestRespectOptOut = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                hashedDiiIdentity,
                OptoutCheckPolicy.RespectOptOut);

        // the clock value shouldn't matter here
        when(optOutStore.getLatestEntry(any(FirstLevelHashIdentity.class)))
                .thenReturn(Instant.now().minus(1, ChronoUnit.HOURS));

        final Identity identity;
        final AdvertisingTokenInput advertisingTokenInput;
        final Identity identityAfterOptOut;
        if (scope == IdentityScope.UID2) {
            identity = uid2Service.generateIdentity(identityRequestForceGenerate);
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            advertisingTokenInput = validateAndGetToken(tokenEncoder, identity.getAdvertisingToken(), IdentityScope.UID2, hashedDiiIdentity.identityType, identityRequestRespectOptOut.publisherIdentity.siteId);
            reset(shutdownHandler);
            identityAfterOptOut = uid2Service.generateIdentity(identityRequestRespectOptOut);

        } else {
            identity = euidService.generateIdentity(identityRequestForceGenerate);
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            advertisingTokenInput = validateAndGetToken(tokenEncoder, identity.getAdvertisingToken(), IdentityScope.EUID, hashedDiiIdentity.identityType, identityRequestRespectOptOut.publisherIdentity.siteId);
            reset(shutdownHandler);
            identityAfterOptOut = euidService.generateIdentity(identityRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identity);
        assertNotNull(advertisingTokenInput.rawUidIdentity);
        assertNotNull(identityAfterOptOut);
        assertTrue(identityAfterOptOut.getAdvertisingToken() == null || identityAfterOptOut.getAdvertisingToken().isEmpty());

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

        final MappedIdentityResult mappedIdentityResult;
        final MappedIdentityResult mappedIdentityResultShouldBeOptOut;
        if (scope == IdentityScope.UID2) {
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            mappedIdentityResult = uid2Service.mapIdentity(mapRequestForceMap);
            reset(shutdownHandler);
            mappedIdentityResultShouldBeOptOut = uid2Service.mapIdentity(mapRequestRespectOptOut);
        } else {
            verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
            verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
            mappedIdentityResult = euidService.mapIdentity(mapRequestForceMap);
            reset(shutdownHandler);
            mappedIdentityResultShouldBeOptOut = euidService.mapIdentity(mapRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(mappedIdentityResult);
        assertFalse(mappedIdentityResult.isOptedOut());
        assertNotNull(mappedIdentityResultShouldBeOptOut);
        assertTrue(mappedIdentityResultShouldBeOptOut.isOptedOut());
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
                inputVal.toHashedDiiIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut
        );

        // identity has no optout record, ensure generate still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        Identity identity;
        if(scope == IdentityScope.EUID) {
            identity = euidService.generateIdentity(identityRequest);
        }
        else {
            identity = uid2Service.generateIdentity(identityRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertEquals(identity, Identity.InvalidIdentity);
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
                inputVal.toHashedDiiIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut,
                now);

        // identity has no optout record, ensure map still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final MappedIdentityResult mappedIdentityResult;
        if(scope == IdentityScope.EUID) {
            mappedIdentityResult = euidService.mapIdentity(mapRequestRespectOptOut);
        }
        else {
            mappedIdentityResult = uid2Service.mapIdentity(mapRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(mappedIdentityResult);
        assertTrue(mappedIdentityResult.isOptedOut());
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
                inputVal.toHashedDiiIdentity(scope, 0, this.now),
                OptoutCheckPolicy.DoNotRespect
        );

        Identity identity;
        if(scope == IdentityScope.EUID) {
            identity = euidService.generateIdentity(identityRequest);
        }
        else {
            identity = uid2Service.generateIdentity(identityRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identity);
        assertNotEquals(Identity.InvalidIdentity, identity);

        // identity has no optout record, ensure refresh still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final RefreshTokenInput refreshTokenInput = this.tokenEncoder.decodeRefreshToken(identity.getRefreshToken());
        reset(shutdownHandler);
        assertEquals(RefreshResponse.Optout, (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(refreshTokenInput));
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
                inputVal.toHashedDiiIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut
        );

        // identity has optout record, ensure still generates
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        Identity identity;
        if(scope == IdentityScope.EUID) {
            identity = euidService.generateIdentity(identityRequest);
        }
        else {
            identity = uid2Service.generateIdentity(identityRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identity);
        assertNotEquals(Identity.InvalidIdentity, identity);

        // identity has no optout record, ensure refresh still returns optout
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final RefreshTokenInput refreshTokenInput = this.tokenEncoder.decodeRefreshToken(identity.getRefreshToken());
        reset(shutdownHandler);
        assertEquals(RefreshResponse.Optout, (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(refreshTokenInput));
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
                inputVal.toHashedDiiIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut,
                now);

        // all identities have optout records, ensure refresh-optout identities still map
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        final MappedIdentityResult mappedIdentityResult;
        if(scope == IdentityScope.EUID) {
            mappedIdentityResult = euidService.mapIdentity(mapRequestRespectOptOut);
        }
        else {
            mappedIdentityResult = uid2Service.mapIdentity(mapRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(mappedIdentityResult);
        assertFalse(mappedIdentityResult.isOptedOut());
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
                inputVal.toHashedDiiIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut
        );

        // all identities have optout records, ensure validate identities still get generated
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        Identity identity;
        AdvertisingTokenInput advertisingTokenInput;
        if (scope == IdentityScope.EUID) {
            identity = euidService.generateIdentity(identityRequest);
        }
        else {
            identity = uid2Service.generateIdentity(identityRequest);
        }
        advertisingTokenInput = validateAndGetToken(tokenEncoder, identity.getAdvertisingToken(), scope, identityRequest.hashedDiiIdentity.identityType, identityRequest.publisherIdentity.siteId);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(identity);
        assertNotEquals(Identity.InvalidIdentity, identity);
        assertNotNull(advertisingTokenInput.rawUidIdentity);
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
                inputVal.toHashedDiiIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut,
                now);

        // all identities have optout records, ensure validate identities still get mapped
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        final MappedIdentityResult mappedIdentityResult;
        if(scope == IdentityScope.EUID) {
            mappedIdentityResult = euidService.mapIdentity(mapRequestRespectOptOut);
        }
        else {
            mappedIdentityResult = uid2Service.mapIdentity(mapRequestRespectOptOut);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotNull(mappedIdentityResult);
        assertFalse(mappedIdentityResult.isOptedOut());
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
                inputVal.toHashedDiiIdentity(scope, 0, this.now),
                OptoutCheckPolicy.DoNotRespect
        );
        Identity identity;
        if(scope == IdentityScope.EUID) {
            identity = euidService.generateIdentity(identityRequest);
        }
        else {
            identity = uid2Service.generateIdentity(identityRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(false);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(true);
        assertNotEquals(identity, Identity.InvalidIdentity);
        assertNotNull(identity);

        final RefreshTokenInput refreshTokenInput = this.tokenEncoder.decodeRefreshToken(identity.getRefreshToken());
        RefreshResponse refreshResponse = (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(refreshTokenInput);
        assertTrue(refreshResponse.isRefreshed());
        assertNotNull(refreshResponse.getIdentity());
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
                inputVal.toHashedDiiIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut);

        Identity identity;
        AdvertisingTokenInput advertisingTokenInput;
        reset(shutdownHandler);
        if(scope == IdentityScope.EUID) {
            identity = euidService.generateIdentity(identityRequest);
            advertisingTokenInput = validateAndGetToken(tokenEncoder, identity.getAdvertisingToken(), IdentityScope.EUID, identityRequest.hashedDiiIdentity.identityType, identityRequest.publisherIdentity.siteId);
        }
        else {
            identity = uid2Service.generateIdentity(identityRequest);
            advertisingTokenInput = validateAndGetToken(tokenEncoder, identity.getAdvertisingToken(), IdentityScope.UID2, identityRequest.hashedDiiIdentity.identityType, identityRequest.publisherIdentity.siteId);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(false);
        assertNotNull(identity);
        assertNotEquals(Identity.InvalidIdentity, identity);
        assertNotNull(advertisingTokenInput.rawUidIdentity);

        final RefreshTokenInput refreshTokenInput = this.tokenEncoder.decodeRefreshToken(identity.getRefreshToken());
        reset(shutdownHandler);
        RefreshResponse refreshResponse = (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(refreshTokenInput);
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(false);
        assertTrue(refreshResponse.isRefreshed());
        assertNotNull(refreshResponse.getIdentity());
        assertNotEquals(RefreshResponse.Optout, refreshResponse);

        final MapRequest mapRequest = new MapRequest(
                inputVal.toHashedDiiIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut,
                now);
        final MappedIdentityResult mappedIdentityResult;
        reset(shutdownHandler);
        if(scope == IdentityScope.EUID) {
            mappedIdentityResult = euidService.mapIdentity(mapRequest);
        }
        else {
            mappedIdentityResult = uid2Service.mapIdentity(mapRequest);
        }
        verify(shutdownHandler, atLeastOnce()).handleSaltRetrievalResponse(true);
        verify(shutdownHandler, never()).handleSaltRetrievalResponse(false);
        assertNotNull(mappedIdentityResult);
        assertFalse(mappedIdentityResult.isOptedOut());

    }
}
