package com.polduu.repository;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.polduu.model.AuthProvider;
import com.polduu.model.UserIdentity;

@Repository
public interface UserIdentityRepository extends JpaRepository<UserIdentity, UUID> {

       Optional<UserIdentity> findByProviderAndProviderId(AuthProvider provider, String providerId);

       boolean existsByProviderAndProviderId(AuthProvider provider, String providerId);

       boolean existsByUserIdAndProvider(UUID userId, AuthProvider google);
}
