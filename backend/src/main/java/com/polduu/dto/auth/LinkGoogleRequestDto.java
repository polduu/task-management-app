package com.polduu.dto.auth;

import com.polduu.validation.MaxUtf8Bytes;

import jakarta.validation.constraints.NotBlank;

public record LinkGoogleRequestDto(
    @NotBlank(message = "Google ID token is required")
    String idToken,
    // Required when the account has a password
    @MaxUtf8Bytes(value = 72, message = "Password is too long")
    String password
) {}
