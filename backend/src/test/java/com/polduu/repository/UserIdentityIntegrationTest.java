package com.polduu.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Transactional;

import com.polduu.TestcontainersConfiguration;
import com.polduu.model.AuthProvider;
import com.polduu.model.User;
import com.polduu.model.UserIdentity;

/** Identity mapping and constraints against the real Flyway schema. Rolled back after each test. */
@SpringBootTest(properties = TestcontainersConfiguration.PROPERTIES)
@Import(TestcontainersConfiguration.class)
@Transactional
class UserIdentityIntegrationTest {

    @Autowired UserRepository userRepository;
    @Autowired UserIdentityRepository userIdentityRepository;

    @Test
    void user_canLinkOneAccountPerProvider() {
        User user = newUser("identity_one");
        save(user, AuthProvider.GOOGLE, "google-1");
        save(user, AuthProvider.GITHUB, "github-1");

        assertThat(userIdentityRepository.findByProviderAndProviderId(AuthProvider.GITHUB, "github-1"))
                .map(identity -> identity.getUser().getId())
                .contains(user.getId());
        assertThat(userIdentityRepository.existsByUserIdAndProvider(user.getId(), AuthProvider.GOOGLE)).isTrue();
    }

    @Test
    void secondAccountOfTheSameProvider_isRejected() {
        User user = newUser("identity_two");
        save(user, AuthProvider.GOOGLE, "google-2");

        assertThatThrownBy(() -> save(user, AuthProvider.GOOGLE, "google-3"))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void sameExternalAccountForTwoUsers_isRejected() {
        save(newUser("identity_three"), AuthProvider.GITHUB, "github-4");
        User other = newUser("identity_four");

        assertThatThrownBy(() -> save(other, AuthProvider.GITHUB, "github-4"))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    private User newUser(String username) {
        return userRepository.saveAndFlush(User.builder()
                .username(username).email(username + "@test.com").fullName("Pol").build());
    }

    private void save(User user, AuthProvider provider, String providerId) {
        UserIdentity identity = new UserIdentity();
        identity.setUser(user);
        identity.setProvider(provider);
        identity.setProviderId(providerId);
        userIdentityRepository.saveAndFlush(identity);
    }
}
