package com.polduu.dto.auth;

import jakarta.validation.constraints.NotBlank;

public record GoogleAuthRequestDto(
    
    @NotBlank (message = "Google ID token is required")
    String idToken // The ID token received from the client after Google authentication 
) {
}
