package com.uid2.operator.service;

import com.uid2.shared.cloud.CloudStorageException;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.uid2.operator.service.TokenUtils.getSiteIdsUsingV4Tokens;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class TokenUtilsTest {
    Set<Integer> siteIdsV4TokensSet = new HashSet<>(Arrays.asList(127, 128));
    @Test
    void getSiteIdsUsingV4Tokens_multipleSiteIds() {
        Set<Integer> actualSiteIdsV4TokensSet = getSiteIdsUsingV4Tokens("127, 128");
        assertEquals(siteIdsV4TokensSet, actualSiteIdsV4TokensSet);
    }

    @Test
    void getSiteIdsUsingV4Tokens_oneSiteIds() {
        Set<Integer> actualSiteIdsV4TokensSet = getSiteIdsUsingV4Tokens("127");
        assertEquals(new HashSet<>(List.of(127)), actualSiteIdsV4TokensSet);
    }

    @Test
    void getSiteIdsUsingV4Tokens_emptyInput() {
        Set<Integer> actualSiteIdsV4TokensSet = getSiteIdsUsingV4Tokens("");
        assertEquals(new HashSet<>(), actualSiteIdsV4TokensSet);
    }

    @Test
    void getSiteIdsUsingV4Tokens_inputContainsSpaces() {
        Set<Integer> actualSiteIdsV4TokensSet = getSiteIdsUsingV4Tokens(" 127 ,128 ");
        assertEquals(siteIdsV4TokensSet, actualSiteIdsV4TokensSet);
    }

    @Test
    void getSiteIdsUsingV4Tokens_inputContainsInvalidInteger() {
        assertThrows(IllegalArgumentException.class,
                () -> getSiteIdsUsingV4Tokens(" 1 27 ,128 "));
    }
}
