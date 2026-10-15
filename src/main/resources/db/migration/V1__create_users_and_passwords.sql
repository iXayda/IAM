CREATE TABLE iam_user (
    id UUID PRIMARY KEY,
    username VARCHAR(64) COLLATE "C" NOT NULL,
    display_name VARCHAR(128) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT iam_user_username_unique UNIQUE (username),
    CONSTRAINT iam_user_username_format CHECK (username ~ '^[a-z0-9._-]{3,64}$'),
    CONSTRAINT iam_user_display_name_length CHECK (char_length(display_name) >= 1),
    CONSTRAINT iam_user_status CHECK (status IN ('pending', 'active', 'disabled'))
);

CREATE TABLE iam_password (
    user_id UUID PRIMARY KEY REFERENCES iam_user (id) ON DELETE RESTRICT,
    password_hash VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT iam_password_hash_format CHECK (
        password_hash ~ '^\$argon2id\$v=19\$m=[0-9]{1,6},t=[0-9]{1,2},p=[0-9]{1,2}\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$'
    )
);
