package com.fpa.springoath2api.security.user;

import com.fpa.springoath2api.exception.OAuth2AuthenticationProcessingException;
import com.fpa.springoath2api.model.AuthProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

public class OAuth2UserFactory {

    private final static Logger logger = LoggerFactory.getLogger(OAuth2UserFactory.class);

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {

        logger.debug("Get regId: {}, attributes {}", registrationId, attributes);

        if(registrationId.equalsIgnoreCase(AuthProvider.google.toString())) {
            return new GoogleOAuth2UserInfo((Map<String, Object>) attributes.get("User Attributes"));
        } else if (registrationId.equalsIgnoreCase(AuthProvider.github.toString())) {
            return new GithubOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(AuthProvider.bitrix.toString())) {
            return new BitrixOAuth2UserInfo((Map<String, Object>) attributes.get("result"));
        } else {
            throw new OAuth2AuthenticationProcessingException("Sorry! Login with " + registrationId + " is not supported yet.");
        }
    }
}
