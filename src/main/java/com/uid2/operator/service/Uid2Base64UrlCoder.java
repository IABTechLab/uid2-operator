package com.uid2.operator.service;

import java.util.Base64;

class Uid2Base64UrlCoder {
    //always use this interface to encode/decode Base64URL standard with no padding
    //as specified on https://www.rfc-editor.org/rfc/rfc4648#section-5
    //as unit test assumes that we are testing the encoding/decoding lib used here
    public static String encode(byte[] bytes)
    {
        String encoded = Base64.getUrlEncoder().encodeToString(bytes);
        int paddingCount = 0;
        int len = encoded.length();
        for(int i = 0; i < 3; i++)
        {
            if(len - 1 - i < 0)
            {
                break;
            }
            if(encoded.charAt(len - 1 - i) == '=')
            {
                paddingCount++;
            }
            else //'=' has to be at the very back
            {
                break;
            }
        }
        if(paddingCount > 0)
        {
            //need to remove '=' padding to make it more URL friendly
            return encoded.substring(0, len - paddingCount);
        }
        return encoded;
    }

    public static byte[] decode(String str)
    {
        return Base64.getUrlDecoder().decode(str);
    }
}
