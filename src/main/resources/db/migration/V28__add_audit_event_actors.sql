ALTER TABLE audit_events
    ADD COLUMN actor_user_id UUID;

CREATE INDEX audit_events_tenant_actor_occurred_idx
    ON audit_events (tenant_id, actor_user_id, occurred_at DESC, event_id DESC)
    WHERE actor_user_id IS NOT NULL;
