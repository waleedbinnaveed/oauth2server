package com.example.authorizationserver.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return successAuthenticationResponse();
    }

    private Authentication successAuthenticationResponse() {
        UsernamePasswordAuthenticationToken token=new UsernamePasswordAuthenticationToken("username", "paswword",null);
        return token;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return false;
    }
}
