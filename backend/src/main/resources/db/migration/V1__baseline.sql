CREATE TABLE users (
    id            uuid                        NOT NULL,
    auth_provider varchar(255)                NOT NULL,
    created_at    timestamp(6) with time zone NOT NULL,
    email         varchar(255)                NOT NULL,
    full_name     varchar(100)                NOT NULL,
    image_url     varchar(500),
    password_hash varchar(60),
    provider_id   varchar(255),
    username      varchar(50)                 NOT NULL,
    CONSTRAINT users_pkey PRIMARY KEY (id),
    CONSTRAINT uk6dotkott2kjsp8vw4d0m25fb7 UNIQUE (email),
    CONSTRAINT ukr43af9ap4edm43mmtq01oddj6 UNIQUE (username),
    CONSTRAINT uk438461sdkk3sk20tsac99ka6a UNIQUE (auth_provider, provider_id),
    CONSTRAINT users_auth_provider_check CHECK (auth_provider IN ('LOCAL', 'GOOGLE', 'GITHUB'))
);

CREATE TABLE refresh_tokens (
    id                uuid                        NOT NULL,
    created_at        timestamp(6) with time zone NOT NULL,
    expires_at        timestamp(6) with time zone NOT NULL,
    family_expires_at timestamp(6) with time zone NOT NULL,
    family_id         uuid                        NOT NULL,
    revoked_at        timestamp(6) with time zone,
    token_hash        varchar(64)                 NOT NULL,
    used_at           timestamp(6) with time zone,
    user_id           uuid                        NOT NULL,
    CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT uko2mlirhldriil2y7krapq4frt UNIQUE (token_hash),
    CONSTRAINT fk1lih5y2npsf8u5o3vhdb9y0os FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens (family_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
