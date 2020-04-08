package com.fpa.springoath2api.security.user;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Map;

public class BitrixOAuth2UserInfo extends OAuth2UserInfo {
    public BitrixOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return ((Integer) attributes.get("ID")).toString();
    }

    @Override
    public String getName() {
        return (String) attributes.get("NAME");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("EMAIL");
    }
}
