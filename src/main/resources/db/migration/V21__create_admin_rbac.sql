CREATE TABLE admin_permissions (
    permission_code TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT admin_permissions_code_check
        CHECK (
            char_length(permission_code) BETWEEN 3 AND 100
            AND permission_code ~ '^[a-z][a-z0-9_]*([.][a-z][a-z0-9_]*)+$'
        ),
    CONSTRAINT admin_permissions_name_check
        CHECK (
            name = btrim(name)
            AND char_length(name) BETWEEN 1 AND 120
            AND name !~ '[[:cntrl:]]'
        ),
    CONSTRAINT admin_permissions_description_check
        CHECK (
            description = btrim(description)
            AND char_length(description) BETWEEN 1 AND 500
            AND description !~ '[[:cntrl:]]'
        ),
    CONSTRAINT admin_permissions_status_check
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT admin_permissions_timestamps_check
        CHECK (updated_at >= created_at)
);

CREATE TABLE admin_roles (
    role_code TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    protected_role BOOLEAN NOT NULL DEFAULT false,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT admin_roles_code_check
        CHECK (
            char_length(role_code) BETWEEN 3 AND 80
            AND role_code ~ '^[a-z][a-z0-9_]*$'
        ),
    CONSTRAINT admin_roles_name_check
        CHECK (
            name = btrim(name)
            AND char_length(name) BETWEEN 1 AND 120
            AND name !~ '[[:cntrl:]]'
        ),
    CONSTRAINT admin_roles_description_check
        CHECK (
            description = btrim(description)
            AND char_length(description) BETWEEN 1 AND 500
            AND description !~ '[[:cntrl:]]'
        ),
    CONSTRAINT admin_roles_status_check
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT admin_roles_version_check
        CHECK (version >= 0),
    CONSTRAINT admin_roles_timestamps_check
        CHECK (updated_at >= created_at)
);

CREATE TABLE admin_role_permissions (
    role_code TEXT NOT NULL,
    permission_code TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT admin_role_permissions_pkey
        PRIMARY KEY (role_code, permission_code),
    CONSTRAINT admin_role_permissions_role_fk
        FOREIGN KEY (role_code) REFERENCES admin_roles (role_code) ON DELETE RESTRICT,
    CONSTRAINT admin_role_permissions_permission_fk
        FOREIGN KEY (permission_code) REFERENCES admin_permissions (permission_code) ON DELETE RESTRICT
);

CREATE INDEX admin_role_permissions_permission_role_idx
    ON admin_role_permissions (permission_code, role_code);

CREATE TABLE admin_role_grant_rules (
    granter_role_code TEXT NOT NULL,
    granted_role_code TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT admin_role_grant_rules_pkey
        PRIMARY KEY (granter_role_code, granted_role_code),
    CONSTRAINT admin_role_grant_rules_granter_fk
        FOREIGN KEY (granter_role_code) REFERENCES admin_roles (role_code) ON DELETE RESTRICT,
    CONSTRAINT admin_role_grant_rules_granted_fk
        FOREIGN KEY (granted_role_code) REFERENCES admin_roles (role_code) ON DELETE RESTRICT
);

CREATE INDEX admin_role_grant_rules_granted_granter_idx
    ON admin_role_grant_rules (granted_role_code, granter_role_code);

CREATE TABLE admin_role_bindings (
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role_code TEXT NOT NULL,
    binding_type TEXT NOT NULL,
    created_by_user_id UUID,
    reason TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT admin_role_bindings_pkey
        PRIMARY KEY (tenant_id, user_id, role_code),
    CONSTRAINT admin_role_bindings_user_fk
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT admin_role_bindings_role_fk
        FOREIGN KEY (role_code) REFERENCES admin_roles (role_code) ON DELETE RESTRICT,
    CONSTRAINT admin_role_bindings_creator_fk
        FOREIGN KEY (tenant_id, created_by_user_id)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT admin_role_bindings_type_check
        CHECK (binding_type IN ('permanent', 'jit')),
    CONSTRAINT admin_role_bindings_lifetime_check
        CHECK (
            (binding_type = 'permanent' AND expires_at IS NULL)
            OR (
                binding_type = 'jit'
                AND created_by_user_id IS NOT NULL
                AND reason IS NOT NULL
                AND expires_at IS NOT NULL
                AND expires_at > created_at
                AND expires_at <= created_at + interval '8 hours'
            )
        ),
    CONSTRAINT admin_role_bindings_reason_check
        CHECK (
            reason IS NULL
            OR (
                reason = btrim(reason)
                AND char_length(reason) BETWEEN 1 AND 500
                AND reason !~ '[[:cntrl:]]'
            )
        ),
    CONSTRAINT admin_role_bindings_timestamps_check
        CHECK (updated_at >= created_at),
    CONSTRAINT admin_role_bindings_no_self_grant_check
        CHECK (created_by_user_id IS NULL OR created_by_user_id <> user_id)
);

CREATE INDEX admin_role_bindings_role_user_idx
    ON admin_role_bindings (role_code, tenant_id, user_id);

CREATE INDEX admin_role_bindings_jit_expiry_idx
    ON admin_role_bindings (expires_at, tenant_id, user_id)
    WHERE binding_type = 'jit';

CREATE INDEX admin_role_bindings_creator_idx
    ON admin_role_bindings (tenant_id, created_by_user_id)
    WHERE created_by_user_id IS NOT NULL;

INSERT INTO admin_roles (role_code, name, description, protected_role)
VALUES
    ('super_admin', 'Super Admin', 'Full IAM administration access', true),
    ('admin_manager', 'Admin Manager', 'Manage administrators and role bindings', true),
    ('user_manager', 'User Manager', 'Manage users and sessions', true),
    ('auditor', 'Auditor', 'Read audit and risk events', true),
    ('support', 'Support', 'Read basic user information', true);

INSERT INTO admin_permissions (permission_code, name, description)
VALUES
    ('user.read', 'Read users', 'Read user profile and status'),
    ('user.create', 'Create users', 'Create user accounts'),
    ('user.disable', 'Disable users', 'Disable user accounts'),
    ('user.lock', 'Lock users', 'Lock active user accounts'),
    ('user.restore', 'Restore users', 'Restore disabled user accounts'),
    ('user.delete', 'Delete users', 'Soft delete user accounts'),
    ('user.session.revoke', 'Revoke user sessions', 'Revoke active user sessions'),
    ('admin.read', 'Read admins', 'Read administrator role bindings'),
    ('admin.create', 'Create admins', 'Grant initial administrator access'),
    ('admin.disable', 'Disable admins', 'Disable administrator access'),
    ('admin.role.assign', 'Assign admin roles', 'Assign roles to administrators'),
    ('role.read', 'Read roles', 'Read IAM roles and permissions'),
    ('role.manage', 'Manage roles', 'Manage IAM roles and permission bindings'),
    ('client.read', 'Read clients', 'Read OAuth client registrations'),
    ('client.manage', 'Manage clients', 'Manage OAuth client registrations'),
    ('service_account.read', 'Read service accounts', 'Read machine identities'),
    ('service_account.manage', 'Manage service accounts', 'Manage machine identities'),
    ('security.manage', 'Manage security', 'Manage security-critical configuration'),
    ('access_review.read', 'Read access reviews', 'Read access review campaigns and items'),
    ('access_review.manage', 'Manage access reviews', 'Manage access review campaigns and decisions'),
    ('audit.read', 'Read audit logs', 'Read audit events'),
    ('audit.export', 'Export audit logs', 'Export audit events to approved sinks'),
    ('risk.read', 'Read risk events', 'Read identity and token risk events');

INSERT INTO admin_role_permissions (role_code, permission_code)
SELECT 'super_admin', permission_code
FROM admin_permissions;

INSERT INTO admin_role_permissions (role_code, permission_code)
VALUES
    ('admin_manager', 'admin.read'),
    ('admin_manager', 'admin.create'),
    ('admin_manager', 'admin.disable'),
    ('admin_manager', 'admin.role.assign'),
    ('admin_manager', 'role.read'),
    ('user_manager', 'user.read'),
    ('user_manager', 'user.create'),
    ('user_manager', 'user.disable'),
    ('user_manager', 'user.lock'),
    ('user_manager', 'user.restore'),
    ('user_manager', 'user.delete'),
    ('user_manager', 'user.session.revoke'),
    ('auditor', 'audit.read'),
    ('auditor', 'risk.read'),
    ('support', 'user.read');

INSERT INTO admin_role_grant_rules (granter_role_code, granted_role_code)
VALUES
    ('super_admin', 'super_admin'),
    ('super_admin', 'admin_manager'),
    ('super_admin', 'user_manager'),
    ('super_admin', 'auditor'),
    ('super_admin', 'support'),
    ('admin_manager', 'user_manager'),
    ('admin_manager', 'auditor'),
    ('admin_manager', 'support');
