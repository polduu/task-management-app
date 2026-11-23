package com.polduu.dto.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RefreshTokenRequestDto(
    @NotBlank
    @Size(max = 256)
    String refreshToken
) {}
