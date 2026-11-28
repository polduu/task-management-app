package com.polduu.service;

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.springframework.stereotype.Component;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.polduu.exception.InvalidCredentialsException;

import lombok.extern.slf4j.Slf4j;

/** Verifies Google ID tokens. */
@Slf4j
@Component
public class GoogleAuthClient {

    private final GoogleIdTokenVerifier googleIdTokenVerifier;

    public GoogleAuthClient(GoogleIdTokenVerifier googleIdTokenVerifier) {
        this.googleIdTokenVerifier = googleIdTokenVerifier;
    }

    // The token is never logged: it is a credential and carries personal data
    public GoogleIdToken.Payload verify(String idTokenString) {
        GoogleIdToken idToken;
        try {
            idToken = googleIdTokenVerifier.verify(idTokenString);
        } catch (IOException | GeneralSecurityException e) {
            log.error("Could not verify Google ID token", e);
            throw new InvalidCredentialsException();
        } catch (RuntimeException e) {
            log.warn("Malformed Google ID token: {}", e.getClass().getSimpleName());
            throw new InvalidCredentialsException();
        }
        if (idToken == null) {
            log.warn("Google ID token rejected by the verifier");
            throw new InvalidCredentialsException();
        }
        return idToken.getPayload();
    }
}
