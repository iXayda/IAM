CREATE INDEX audit_events_tenant_recorded_idx
    ON audit_events (tenant_id, recorded_at, event_id);

CREATE INDEX audit_events_recorded_idx
    ON audit_events (recorded_at);
