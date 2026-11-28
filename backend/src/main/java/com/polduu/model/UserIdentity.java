package com.polduu.model;

import java.util.UUID;


import org.hibernate.annotations.UuidGenerator;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity 
@Table(name = "user_identities", uniqueConstraints = @UniqueConstraint(columnNames = {"provider", "provider_id"}))
@Getter 
@Setter 
@NoArgsConstructor 
public class UserIdentity {

    @Id 
    @Column (name = "id", nullable = false, updatable = false)
    @UuidGenerator
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated (EnumType.STRING)
    @Column (name = "provider", nullable = false, length = 20)
    private AuthProvider provider;

    @Column (name = "provider_id", nullable = false, length = 255)
    private String providerId;
}
