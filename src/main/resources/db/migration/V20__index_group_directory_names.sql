CREATE INDEX groups_active_tenant_display_name_idx
    ON groups (tenant_id, lower(display_name), group_id)
    WHERE status = 'active';
