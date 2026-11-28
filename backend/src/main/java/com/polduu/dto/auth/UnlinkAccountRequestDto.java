package com.polduu.dto.auth;

import com.polduu.validation.MaxUtf8Bytes;

public record UnlinkAccountRequestDto(
    // Required when the account has a password
    @MaxUtf8Bytes(value = 72, message = "Password is too long")
    String password
) {}
