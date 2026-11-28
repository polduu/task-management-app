package com.polduu.mapper;

import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;
import org.mapstruct.NullValuePropertyMappingStrategy;

import com.polduu.dto.auth.UserRegisterRequestDto;
import com.polduu.dto.user.PublicUserResponseDto;
import com.polduu.dto.user.UserPatchRequestDto;
import com.polduu.dto.user.UserResponseDto;
import com.polduu.model.User;

import org.mapstruct.ReportingPolicy;

@Mapper(
    componentModel = "spring",
    unmappedTargetPolicy = ReportingPolicy.ERROR
)
public interface UserMapper {

    UserResponseDto toResponse(User user);

    PublicUserResponseDto toPublicResponse(User user);

    @Mapping(target = "passwordHash", source = "passwordHash")
    @Mapping(target = "id", ignore = true)            
    @Mapping(target = "imageUrl", ignore = true)     
    @Mapping(target = "createdAt", ignore = true) 
    User toEntity(UserRegisterRequestDto request, String passwordHash);

    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    @Mapping(target = "id", ignore = true)
    @Mapping (target = "username", ignore = true) // Normalization and uniqueness checks handled in the service layer, not in the mapper
    @Mapping(target = "passwordHash", ignore = true) // Prevents overwriting the password hash during updates
    @Mapping (target = "email", ignore = true) // Prevents overwriting the email during updates
    @Mapping (target = "createdAt", ignore = true) // Prevents overwriting the createdAt timestamp during updates   
    void updateUserFromDto(UserPatchRequestDto dto, @MappingTarget User user);
}
