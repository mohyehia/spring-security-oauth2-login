package com.mohyehia.oauth.config.oauth.user;

import com.mohyehia.oauth.exception.OAuth2AuthenticationProcessingException;
import com.mohyehia.oauth.utils.AppConstant;

import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo retrieveOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if(registrationId.equalsIgnoreCase(AppConstant.GOOGLE_PROVIDER)){
            return new GoogleOAuth2UserInfo(attributes);
        }else if(registrationId.equalsIgnoreCase(AppConstant.FACEBOOK_PROVIDER)){
            return new FacebookOAuth2UserInfo(attributes);
        }else{
            throw new OAuth2AuthenticationProcessingException("Sorry! Login with " + registrationId + " is not supported yet.");
        }
    }
}
