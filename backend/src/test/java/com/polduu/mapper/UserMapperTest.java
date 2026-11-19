package com.polduu.mapper;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;

import com.polduu.dto.auth.UserRegisterRequestDto;
import com.polduu.dto.user.PublicUserResponseDto;
import com.polduu.dto.user.UserPatchRequestDto;
import com.polduu.dto.user.UserResponseDto;
import com.polduu.model.AuthProvider;
import com.polduu.model.User;

class UserMapperTest {

    private final UserMapper mapper = Mappers.getMapper(UserMapper.class);

    private static final UUID ID = UUID.randomUUID();

    private User buildUser() {
        return User.builder()
                .id(ID)
                .username("pol")
                .email("pol@test.com")
                .fullName("Pol")
                .imageUrl("http://old.png")
                .passwordHash("hashed")
                .authProvider(AuthProvider.LOCAL)
                .build();
    }

    // toEntity

    @Test
    void toEntity_mapsAllFields() {
        var request = new UserRegisterRequestDto("pol", "pol@test.com", "secret123", "Pol");

        User user = mapper.toEntity(request, "hashed", AuthProvider.LOCAL);

        assertThat(user.getUsername()).isEqualTo("pol");
        assertThat(user.getEmail()).isEqualTo("pol@test.com");
        assertThat(user.getFullName()).isEqualTo("Pol");
        assertThat(user.getPasswordHash()).isEqualTo("hashed");
        assertThat(user.getAuthProvider()).isEqualTo(AuthProvider.LOCAL);
    }

    @Test
    void toEntity_doesNotLeakPlainPassword() {
        var request = new UserRegisterRequestDto("pol", "pol@test.com", "secret123", "Pol");

        User user = mapper.toEntity(request, "hashed", AuthProvider.LOCAL);

        assertThat(user.getPasswordHash()).isNotEqualTo("secret123");
    }

    @Test
    void toEntity_leavesGeneratedFieldsEmpty() {
        var request = new UserRegisterRequestDto("pol", "pol@test.com", "secret123", "Pol");

        User user = mapper.toEntity(request, "hashed", AuthProvider.LOCAL);

        assertThat(user.getId()).isNull();
        assertThat(user.getImageUrl()).isNull();
    }

    // toResponse / toPublicResponse

    @Test
    void toResponse_mapsAllFields() {
        UserResponseDto dto = mapper.toResponse(buildUser());

        assertThat(dto.id()).isEqualTo(ID);
        assertThat(dto.username()).isEqualTo("pol");
        assertThat(dto.email()).isEqualTo("pol@test.com");
        assertThat(dto.fullName()).isEqualTo("Pol");
        assertThat(dto.imageUrl()).isEqualTo("http://old.png");
    }

    @Test
    void toPublicResponse_mapsPublicFields() {
        PublicUserResponseDto dto = mapper.toPublicResponse(buildUser());

        assertThat(dto.username()).isEqualTo("pol");
        assertThat(dto.fullName()).isEqualTo("Pol");
        assertThat(dto.imageUrl()).isEqualTo("http://old.png");
    }

    // updateUserFromDto

    @Test
    void updateUserFromDto_updatesProvidedFields() {
        User user = buildUser();

        mapper.updateUserFromDto(new UserPatchRequestDto(null, "New Name", "http://new.png"), user);

        assertThat(user.getFullName()).isEqualTo("New Name");
        assertThat(user.getImageUrl()).isEqualTo("http://new.png");
    }

    @Test
    void updateUserFromDto_withNullFields_keepsExistingValues() {
        User user = buildUser();

        mapper.updateUserFromDto(new UserPatchRequestDto(null, null, null), user);

        assertThat(user.getUsername()).isEqualTo("pol");
        assertThat(user.getFullName()).isEqualTo("Pol");
        assertThat(user.getImageUrl()).isEqualTo("http://old.png");
    }

    @Test
    void updateUserFromDto_neverTouchesProtectedFields() {
        User user = buildUser();

        mapper.updateUserFromDto(new UserPatchRequestDto("other", "New Name", "http://new.png"), user);

        assertThat(user.getId()).isEqualTo(ID);
        assertThat(user.getEmail()).isEqualTo("pol@test.com");
        assertThat(user.getPasswordHash()).isEqualTo("hashed");
        assertThat(user.getAuthProvider()).isEqualTo(AuthProvider.LOCAL);
        assertThat(user.getUsername()).isEqualTo("pol");
    }
}