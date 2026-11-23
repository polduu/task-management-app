package com.polduu.dto.auth;

import java.util.Locale;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record UserLoginRequestDto(
    @NotBlank (message = "Email is required")
    @Email (message = "Invalid email format")
    String email,
    @NotBlank (message = "Password is required")
    String password
) {
    // Emails are stored and compared in lowercase
    public UserLoginRequestDto {
        email = email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }
}
