CREATE TABLE refresh_tokens (
        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        user_id BIGINT NOT NULL,
        token TEXT NOT NULL,
        jti TEXT NOT NULL,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
        CONSTRAINT refresh_tokens_jti_unique UNIQUE (jti)
);

CREATE INDEX idx_refresh_tokens_jti ON refresh_tokens (jti);