package com.uid2.operator;

import com.uid2.operator.model.*;
import com.uid2.operator.service.EncodingUtils;
import com.uid2.operator.service.EncryptedTokenEncoder;
import com.uid2.operator.service.InputUtil;
import com.uid2.operator.service.UIDOperatorService;
import com.uid2.operator.store.IOptOutStore;
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
import static org.mockito.Mockito.when;

public class UIDOperatorServiceTest {
    private AutoCloseable mocks;
    @Mock private IOptOutStore optOutStore;
    @Mock private Clock clock;
    EncryptedTokenEncoder tokenEncoder;
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

        final JsonObject config = new JsonObject();
        config.put(UIDOperatorService.IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
        config.put(UIDOperatorService.REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, REFRESH_TOKEN_EXPIRES_AFTER_SECONDS);
        config.put(UIDOperatorService.REFRESH_IDENTITY_TOKEN_AFTER_SECONDS, REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);

        tokenEncoder = new EncryptedTokenEncoder(new KeyManager(keysetKeyStore, keysetProvider));

        setNow(Instant.now());

        uid2Service = new UIDOperatorService(
                config,
                optOutStore,
                saltProvider,
                tokenEncoder,
                this.clock,
                IdentityScope.UID2
        );

        config.put("advertising_token_v3", true);
        config.put("identity_v3", true);

        euidService = new UIDOperatorService(
                config,
                optOutStore,
                saltProvider,
                tokenEncoder,
                this.clock,
                IdentityScope.EUID
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

    private UserIdentity createUserIdentity(String rawIdentityHash) {
        return new UserIdentity(
                IdentityScope.UID2,
                IdentityType.Email,
                rawIdentityHash.getBytes(StandardCharsets.UTF_8),
                0,
                this.now.minusSeconds(234),
                this.now.plusSeconds(12345)
        );
    }

    private AdvertisingToken validateAndGetToken(EncryptedTokenEncoder tokenEncoder, String advertisingTokenString, IdentityScope scope, IdentityType type) {
        UIDOperatorVerticleTest.validateAdvertisingToken(advertisingTokenString, scope == IdentityScope.EUID ? TokenVersion.V3 : TokenVersion.V2, scope, type);
        return tokenEncoder.decodeAdvertisingToken(advertisingTokenString);
    }

    @Test
    public void testGenerateAndRefresh() {
        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                createUserIdentity("test-email-hash"),
                OptoutCheckPolicy.DoNotRespect
        );
        final IdentityTokens tokens = uid2Service.generateIdentity(identityRequest);
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

        final RefreshResponse refreshResponse = uid2Service.refreshIdentity(refreshToken);
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
        assertNotNull(tokens);

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        assertEquals(RefreshResponse.Invalid, uid2Service.refreshIdentity(refreshToken));
    }

    @Test
    public void testGenerateTokenForOptOutUser() {
        final UserIdentity userIdentity = createUserIdentity("test-email-hash-previously-opted-out");

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

        final IdentityTokens tokens = uid2Service.generateIdentity(identityRequestForceGenerate);
        AdvertisingToken advertisingToken = validateAndGetToken(tokenEncoder, tokens.getAdvertisingToken(), IdentityScope.UID2, userIdentity.identityType);
        assertNotNull(tokens);
        assertNotNull(advertisingToken.userIdentity);

        final IdentityTokens tokensAfterOptOut = uid2Service.generateIdentity(identityRequestRespectOptOut);
        assertNotNull(tokensAfterOptOut);
        assertTrue(tokensAfterOptOut.getAdvertisingToken() == null || tokensAfterOptOut.getAdvertisingToken().isEmpty());
    }

    @Test
    public void testIdentityMapForOptOutUser() {
        final UserIdentity userIdentity = createUserIdentity("test-email-hash-previously-opted-out");
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

        final MappedIdentity mappedIdentity = uid2Service.mapIdentity(mapRequestForceMap);
        assertNotNull(mappedIdentity);
        assertFalse(mappedIdentity.isOptedOut());

        final MappedIdentity mappedIdentityShouldBeOptOut = uid2Service.mapIdentity(mapRequestRespectOptOut);
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
    public void testSpecialIdentityOptOutTokenGenerate(TestIdentityInputType type, String id, IdentityScope scope) {
        InputUtil.InputVal inputVal = generateInputVal(type, id);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toUserIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut
        );

        // none optout, generated is still opted out with RespectOptOut
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        IdentityTokens tokens;
        if(scope == IdentityScope.EUID) {
            tokens = euidService.generateIdentity(identityRequest);
        }
        else {
            tokens = uid2Service.generateIdentity(identityRequest);
        }
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
    public void testSpecialIdentityOptOutIdentityMap(TestIdentityInputType type, String id, IdentityScope scope) {
        InputUtil.InputVal inputVal = generateInputVal(type, id);

        final MapRequest mapRequestRespectOptOut = new MapRequest(
                inputVal.toUserIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut,
                now);

        // none optout, mapped is still opted out with RespectOptOut
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final MappedIdentity mappedIdentity;
        if(scope == IdentityScope.EUID) {
            mappedIdentity = euidService.mapIdentity(mapRequestRespectOptOut);
        }
        else {
            mappedIdentity = uid2Service.mapIdentity(mapRequestRespectOptOut);
        }
        assertNotNull(mappedIdentity);
        assertTrue(mappedIdentity.isOptedOut());
    }

    //UID2 uses v2 tokens but v2 doesn't handle phone number IdentityType correctly
    //so passing in a phone number and it will be still casted as an email type in UserIdentity
    //and UserIdentity won't match to the default UIDOperatorService.testAlwaysOptInIdentityForPhone
    //as the IdentityType won't match
    //will only test when we switch to v4 token
    //this works for EUID because EUID is on v3 token already which persists to correct IdentityType
    @ParameterizedTest
    @CsvSource({"Email,optout@example.com,UID2",
            "EmailHash,optout@example.com,UID2",
            "Email,optout@example.com,EUID",
            "EmailHash,optout@example.com,EUID",
            "Phone,+00000000000,UID2",
            "PhoneHash,+00000000000,UID2",
            "Phone,+00000000000,EUID",
            "PhoneHash,+00000000000,EUID"})
    public void testSpecialIdentityOptOutTokenRefresh(TestIdentityInputType type, String id, IdentityScope scope) {
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
        assertNotNull(tokens);

        // none optout, refreshed is still opted out after generating with DoNotRespect
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        assertEquals(RefreshResponse.Optout, (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(refreshToken));
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
    public void testSpecialIdentityOptOutGenerateRefresh(TestIdentityInputType type, String id, IdentityScope scope) {
        InputUtil.InputVal inputVal = generateInputVal(type, id);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toUserIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut
        );

        // all optout, still generates
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        IdentityTokens tokens;
        if(scope == IdentityScope.EUID) {
            tokens = euidService.generateIdentity(identityRequest);
        }
        else {
            tokens = uid2Service.generateIdentity(identityRequest);
        }
        assertNotNull(tokens);

        // none optout, refresh is still opted out
        when(this.optOutStore.getLatestEntry(any())).thenReturn(null);

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        assertEquals(RefreshResponse.Optout, (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(refreshToken));
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
    public void testSpecialIdentityOptOutRefreshIdentityMap(TestIdentityInputType type, String id, IdentityScope scope) {
        InputUtil.InputVal inputVal = generateInputVal(type, id);

        final MapRequest mapRequestRespectOptOut = new MapRequest(
                inputVal.toUserIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut,
                now);

        // all optout, still maps
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        final MappedIdentity mappedIdentity;
        if(scope == IdentityScope.EUID) {
            mappedIdentity = euidService.mapIdentity(mapRequestRespectOptOut);
        }
        else {
            mappedIdentity = uid2Service.mapIdentity(mapRequestRespectOptOut);
        }
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
    public void testSpecialIdentityValidateGenerate(TestIdentityInputType type, String id, IdentityScope scope) {
        InputUtil.InputVal inputVal = generateInputVal(type, id);

        final IdentityRequest identityRequest = new IdentityRequest(
                new PublisherIdentity(123, 124, 125),
                inputVal.toUserIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut
        );

        // all optout, still generates
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        IdentityTokens tokens;
        if(scope == IdentityScope.EUID) {
            tokens = euidService.generateIdentity(identityRequest);
        }
        else {
            tokens = uid2Service.generateIdentity(identityRequest);
        }
        assertNotNull(tokens);
        AdvertisingToken advertisingToken = validateAndGetToken(tokenEncoder, tokens.getAdvertisingToken(), scope, identityRequest.userIdentity.identityType);
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
    public void testSpecialIdentityValidateIdentityMap(TestIdentityInputType type, String id, IdentityScope scope) {
        InputUtil.InputVal inputVal = generateInputVal(type, id);

        final MapRequest mapRequestRespectOptOut = new MapRequest(
                inputVal.toUserIdentity(scope, 0, this.now),
                OptoutCheckPolicy.RespectOptOut,
                now);

        // all optout, still maps
        when(this.optOutStore.getLatestEntry(any())).thenReturn(Instant.now());

        final MappedIdentity mappedIdentity;
        if(scope == IdentityScope.EUID) {
            mappedIdentity = euidService.mapIdentity(mapRequestRespectOptOut);
        }
        else {
            mappedIdentity = uid2Service.mapIdentity(mapRequestRespectOptOut);
        }
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
    public void testNormalIdentityOptIn(TestIdentityInputType type, String id, IdentityScope scope) {
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
        assertNotEquals(tokens, IdentityTokens.LogoutToken);
        assertNotNull(tokens);

        final RefreshToken refreshToken = this.tokenEncoder.decodeRefreshToken(tokens.getRefreshToken());
        RefreshResponse refreshResponse = (scope == IdentityScope.EUID? euidService: uid2Service).refreshIdentity(refreshToken);
        assertTrue(refreshResponse.isRefreshed());
        assertNotNull(refreshResponse.getTokens());
        assertNotEquals(RefreshResponse.Optout, refreshResponse);
    }
}
