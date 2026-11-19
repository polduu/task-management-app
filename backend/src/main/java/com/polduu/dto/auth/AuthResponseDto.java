package com.polduu.dto.auth;

import com.polduu.dto.user.UserResponseDto;

public record AuthResponseDto(
    String accessToken,
    String refreshToken,
    Long expiresIn,     // Ex: 900 (segons)
    UserResponseDto user
) {}