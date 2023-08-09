package com.uid2.operator.util;

import com.google.common.net.InternetDomainName;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;

public class DomainNameCheckUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(DomainNameCheckUtil.class);
    private static final String LOCALHOST_DOMAIN_NAME = "localhost";
    public static boolean isDomainNameAllowed(String origin, Set<String> allowedDomainNameSet) {
        URL url;
        try
        {
            url = new URL(origin);
        }
        catch (MalformedURLException e)
        {
            LOGGER.error("isDomainNameAllowed Origin="+origin+" is malformed URL. Rejecting.");
            return false;
        }

        //InternetDomainName will normalise the domain name to lower case already
        InternetDomainName name = InternetDomainName.from(url.getHost());
        //if the domain name has a proper TLD suffix
        if(name.isUnderPublicSuffix())
        {
            try
            {
                String topPrivateDomain = name.topPrivateDomain().toString();
                return allowedDomainNameSet.contains(topPrivateDomain);
            }
            catch(Exception e)
            {
                LOGGER.error("isDomainNameAllowed Origin"+origin+" not producing top level domain name correctly:." + e);
                return false;
            }

        }
        //we make an except for localhost for testing purpose only (and only if we allow it in the
        //allowed domain name set
        else if(allowedDomainNameSet.contains(LOCALHOST_DOMAIN_NAME))
        {
            if(name.hasParent() && name.parent().toString().equals(LOCALHOST_DOMAIN_NAME))
            {
                return true;
            }
            else if(name.toString().equals(LOCALHOST_DOMAIN_NAME))
            {
                return true;
            }
        }
        return false;
    }

    public String getTopLevelDomainName(String origin) throws MalformedURLException
    {
        URL url = new URL(origin);

        //InternetDomainName will normalise the domain name to lower case already
        InternetDomainName name = InternetDomainName.from(url.getHost());
        //if the domain name has a proper TLD suffix
        if(name.isUnderPublicSuffix())
        {
            try
            {
                return name.topPrivateDomain().toString();
            }
            catch(Exception e)
            {
                return null;
            }

        }
        //we make an except for localhost for testing purpose only (and only if we allow it in the
        //allowed domain name set
        if(name.hasParent() && name.parent().toString().equals(LOCALHOST_DOMAIN_NAME))
        {
            return LOCALHOST_DOMAIN_NAME;
        }
        else if(name.toString().equals(LOCALHOST_DOMAIN_NAME))
        {
            return LOCALHOST_DOMAIN_NAME;
        }
    }
}
