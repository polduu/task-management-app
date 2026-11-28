package com.polduu.dto.auth;

import java.util.List;

import com.polduu.model.AuthProvider;

public record LinkedAccountsResponseDto(
    List<AuthProvider> providers,
    // Tells the client whether to ask for the password before linking or unlinking
    boolean hasPassword
) {}
