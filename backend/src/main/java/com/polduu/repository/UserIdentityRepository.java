package com.polduu.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.polduu.model.AuthProvider;
import com.polduu.model.UserIdentity;

@Repository
public interface UserIdentityRepository extends JpaRepository<UserIdentity, UUID> {

    // Loads the user too: GitHub login reads it outside a transaction
    @EntityGraph(attributePaths = "user")
    Optional<UserIdentity> findByProviderAndProviderId(AuthProvider provider, String providerId);

    Optional<UserIdentity> findByUserIdAndProvider(UUID userId, AuthProvider provider);

    boolean existsByUserIdAndProvider(UUID userId, AuthProvider provider);

    long countByUserId(UUID userId);

    List<UserIdentity> findByUserId(UUID userId);
}
