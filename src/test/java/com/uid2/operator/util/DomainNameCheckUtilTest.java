package com.uid2.operator.util;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

import static com.uid2.operator.util.DomainNameCheckUtil.isDomainNameAllowed;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DomainNameCheckUtilTest {
    @ParameterizedTest
    @ValueSource(strings = {
            "http://examplewebsite.com",
            "https://examplewebsite.com",
            "https://abc.examplewebsite.com:8080",
            "https://abc.examplewebsite.com:8080/",
            "https://abc.eXampleWebsIte.com:8080/",
            "https://abc.exAmplewEbsite.com:8080/blahh/a.html",

            "http://e-wb.org",
            "https://e-wb.org",
            "https://abc.e-wb.org:8080",
            "https://abc.e-wb.org:8080/",
            "https://abc.e-Wb.org:8080/",
            "https://abc.e-wb.org:8080/blahh/a.html",

            "http://aussiedomain.id.au",
            "https://aussiedomain.id.au/head.html"
    })
    void testDomainNameCheckSuccess(String origin) {
        Set<String> allowedDomainNamesForProd = Set.of("examplewebsite.com","e-wb.org","aussiedomain.id.au");

        assertTrue(isDomainNameAllowed(origin, allowedDomainNamesForProd));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://localhost",
            "https://localhost:8080/",
            "https://abc.localhost:8080",
            "https://abc.localhost:8080/",
            "https://abc.locaLHost:8080/",
            "https://abc.localhost:8080/blahh/a.html"
    })
    void testLocalhostDomainNameCheck(String origin) {
        Set<String> allowedDomainNamesForTesting = Set.of("examplewebsite.com", "e-wb.org", "localhost");

        assertTrue(isDomainNameAllowed(origin, allowedDomainNamesForTesting));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            // Malformed URLs
            "examplewebsite.com",
            "examplewebsite.com:999999",
            "abc:examplewebsite.com",
            "/:$2231examplewebsite.com",
            "/:$2231examplewebsite.com/23423/sfs.html",

            // Disallowed domain names
            "http://boohoo.id.au",
            "https://blah12.com",
            "http://123.boohoo.id.au",
            "https://456.blah12.com"
    })
    void testDomainNameCheckFailure(String origin) {
        Set<String> allowedDomainNamesForProd = Set.of("examplewebsite.com", "e-wb.org", "aussiedomain.id.au");

        assertFalse(isDomainNameAllowed(origin, allowedDomainNamesForProd));
    }
}
