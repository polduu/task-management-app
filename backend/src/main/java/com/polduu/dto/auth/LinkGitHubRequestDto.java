package com.polduu.dto.auth;

import com.polduu.validation.MaxUtf8Bytes;

import jakarta.validation.constraints.NotBlank;

public record LinkGitHubRequestDto(
    @NotBlank(message = "GitHub authorization code is required")
    String code,
    // Required when the account has a password
    @MaxUtf8Bytes(value = 72, message = "Password is too long")
    String password
) {}
