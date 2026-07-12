CREATE TABLE tenants (
    tenant_id UUID PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),
    version BIGINT NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        char_length(slug) BETWEEN 1 AND 63
        AND slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'
        AND slug !~ '-$'
    ),
    CHECK (char_length(btrim(display_name)) BETWEEN 1 AND 200),
    CHECK (
        tenant_id <> '00000000-0000-0000-0000-000000000001'
        OR (slug = 'default' AND status = 'active')
    )
);

INSERT INTO tenants (tenant_id, slug, display_name, status)
VALUES ('00000000-0000-0000-0000-000000000001', 'default', 'Default', 'active');
