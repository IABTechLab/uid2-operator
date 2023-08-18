package com.uid2.operator;

import com.google.common.net.InternetDomainName;
import com.uid2.operator.util.DomainNameCheckUtil;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static com.uid2.operator.util.DomainNameCheckUtil.isDomainNameAllowed;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


public class DomainNameCheckUtilTest {

    @Test
    public void testDomainNameCheckSuccess() throws MalformedURLException {
        Set<String> allowedDomainNamesForProd = new HashSet<>(Arrays.asList("examplewebsite.com","e-wb.org","aussiedomain.id.au"));

        //most basic examples
        assertTrue(isDomainNameAllowed("http://examplewebsite.com", allowedDomainNamesForProd));
        assertTrue(isDomainNameAllowed("https://examplewebsite.com", allowedDomainNamesForProd));
        //added subdomain and port number
        assertTrue(isDomainNameAllowed("https://abc.examplewebsite.com:8080", allowedDomainNamesForProd));
        //added slash
        assertTrue(isDomainNameAllowed("https://abc.examplewebsite.com:8080/", allowedDomainNamesForProd));
        //domain name casing is not all lower cased
        assertTrue(isDomainNameAllowed("https://abc.eXampleWebsIte.com:8080/", allowedDomainNamesForProd));
        //points to a specific file and subdirectory
        assertTrue(isDomainNameAllowed("https://abc.exAmplewEbsite.com:8080/blahh/a.html", allowedDomainNamesForProd));

        //testing a bit more weird domain name
        assertTrue(isDomainNameAllowed("http://e-wb.org", allowedDomainNamesForProd));
        assertTrue(isDomainNameAllowed("https://e-wb.org", allowedDomainNamesForProd));
        //added subdomain and port number
        assertTrue(isDomainNameAllowed("https://abc.e-wb.org:8080", allowedDomainNamesForProd));
        //added slash
        assertTrue(isDomainNameAllowed("https://abc.e-wb.org:8080/", allowedDomainNamesForProd));
        //domain name casing is not all lower cased
        assertTrue(isDomainNameAllowed("https://abc.e-wb.org:8080/", allowedDomainNamesForProd));
        //points to a specific file and subdirectory
        assertTrue(isDomainNameAllowed("https://abc.e-wb.org:8080/blahh/a.html", allowedDomainNamesForProd));

        //testing for TLD with 2 suffixes (.id.au)
        assertTrue(isDomainNameAllowed("http://aussiedomain.id.au", allowedDomainNamesForProd));
        assertTrue(isDomainNameAllowed("https://aussiedomain.id.au/head.html", allowedDomainNamesForProd));
    }

    @Test
    public void testDomainNameCheckFailure() throws MalformedURLException {

        Set<String> allowedDomainNamesForProd = new HashSet<>(Arrays.asList("examplewebsite.com","e-wb.org","aussiedomain.id.au"));

        //a few malformed URLs
        assertFalse(isDomainNameAllowed("examplewebsite.com", allowedDomainNamesForProd));
        assertFalse(isDomainNameAllowed("examplewebsite.com:999999", allowedDomainNamesForProd));
        assertFalse(isDomainNameAllowed("abc:examplewebsite.com", allowedDomainNamesForProd));
        assertFalse(isDomainNameAllowed("/:$2231examplewebsite.com", allowedDomainNamesForProd));
        assertFalse(isDomainNameAllowed("/:$2231examplewebsite.com/23423/sfs.html", allowedDomainNamesForProd));

        //reject disallowed domain names
        assertFalse(isDomainNameAllowed("http://boohoo.id.au", allowedDomainNamesForProd));
        assertFalse(isDomainNameAllowed("https://blah12.com", allowedDomainNamesForProd));
        assertFalse(isDomainNameAllowed("http://123.boohoo.id.au", allowedDomainNamesForProd));
        assertFalse(isDomainNameAllowed("https://456.blah12.com", allowedDomainNamesForProd));
    }

    @Test
    public void testLocalhostDomainNameCheck()
    {
        Set<String> allowedDomainNamesForTesting = new HashSet<>(Arrays.asList("examplewebsite.com","e-wb.org","localhost"));
        //most basic examples
        assertTrue(isDomainNameAllowed("http://localhost", allowedDomainNamesForTesting));
        assertTrue(isDomainNameAllowed("https://localhost:8080/", allowedDomainNamesForTesting));
        //added subdomain and port number
        assertTrue(isDomainNameAllowed("https://abc.localhost:8080", allowedDomainNamesForTesting));
        //added slash
        assertTrue(isDomainNameAllowed("https://abc.localhost:8080/", allowedDomainNamesForTesting));
        //domain name casing is not all lower cased
        assertTrue(isDomainNameAllowed("https://abc.locaLHost:8080/", allowedDomainNamesForTesting));
        //points to a specific file and subdirectory
        assertTrue(isDomainNameAllowed("https://abc.localhost:8080/blahh/a.html", allowedDomainNamesForTesting));
    }
}
