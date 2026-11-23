package com.polduu.dto.auth;

import java.util.Locale;

import com.polduu.validation.MaxUtf8Bytes;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record UserRegisterRequestDto(
    @NotBlank
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Username can only contain letters, numbers, and underscores")
    String username,
    @NotBlank
    @Email
    @Size(max = 255, message = "Email must be at most 255 characters")
    String email,
    @NotBlank
    @Size(min = 6, message = "Password must be at least 6 characters long")
    @MaxUtf8Bytes(value = 72, message = "Password is too long")
    String password,
    @NotBlank
    @Size(max = 100, message = "Full name must be at most 100 characters")
    String fullName
) {
    // Emails are stored and compared in lowercase
    public UserRegisterRequestDto {
        email = email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }
}
