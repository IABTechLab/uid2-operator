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
        String topLevelDomainName;
        try
        {
            topLevelDomainName = getTopLevelDomainName(origin);
        }
        catch (MalformedURLException e) {
            LOGGER.error("isDomainNameAllowed Origin="+origin+" is malformed URL. Rejecting.");
            return false;
        }
        catch (Exception e) {
            LOGGER.error("isDomainNameAllowed Origin"+origin+" not producing top level domain name correctly:." + e +" Rejecting.");
            return false;
        }

        if(topLevelDomainName == null)
        {
            LOGGER.error("isDomainNameAllowed Origin"+origin+" returns null top level domain name value. Rejecting.");
            return false;
        }

        return allowedDomainNameSet.contains(topLevelDomainName);
    }

    // this method can be reused down the line by admin service
    //to make sure admin and operator use the same method to parse top level domain name
    //so we can catch parsing error when we first add the publisher's domain name into the allowed list in admin
    //service (not when operator is starting getting CSTG requests from publisher websites)
    public static String getTopLevelDomainName(String origin) throws MalformedURLException
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
                throw e;
            }

        }
        //we make an exception for localhost for testing purpose only
        if(name.hasParent() && name.parent().toString().equals(LOCALHOST_DOMAIN_NAME))
        {
            return LOCALHOST_DOMAIN_NAME;
        }
        else if(name.toString().equals(LOCALHOST_DOMAIN_NAME))
        {
            return LOCALHOST_DOMAIN_NAME;
        }
        return null;
    }
}
