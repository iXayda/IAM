CREATE TABLE audit_events (
    event_id UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    user_id UUID,
    session_id UUID,
    authentication_factor TEXT,
    source TEXT NOT NULL,
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT audit_events_type_format CHECK (
        length(event_type) BETWEEN 3 AND 120
        AND event_type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'
    ),
    CONSTRAINT audit_events_outcome_values CHECK (
        outcome IN ('succeeded', 'failed', 'challenged', 'throttled', 'unavailable')
    ),
    CONSTRAINT audit_events_factor_values CHECK (
        authentication_factor IS NULL
        OR authentication_factor IN ('password', 'totp', 'recovery_code')
    ),
    CONSTRAINT audit_events_source_format CHECK (
        length(source) BETWEEN 1 AND 512
        AND source !~ '[^\x21-\x7e]'
    ),
    CONSTRAINT audit_events_attributes_object CHECK (
        jsonb_typeof(attributes) = 'object' AND octet_length(attributes::text) <= 8192
    ),
    CONSTRAINT audit_events_occurred_at_epoch CHECK (occurred_at >= TIMESTAMPTZ '1970-01-01 00:00:00+00'),
    CONSTRAINT audit_events_recorded_at_epoch CHECK (recorded_at >= TIMESTAMPTZ '1970-01-01 00:00:00+00')
);

CREATE INDEX audit_events_tenant_timeline_idx
    ON audit_events (tenant_id, occurred_at DESC, event_id DESC);

CREATE INDEX audit_events_tenant_type_timeline_idx
    ON audit_events (tenant_id, event_type, occurred_at DESC, event_id DESC);

CREATE FUNCTION reject_audit_event_mutation() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER audit_events_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events
    FOR EACH STATEMENT
    EXECUTE FUNCTION reject_audit_event_mutation();
