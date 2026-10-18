CREATE INDEX iam_security_audit_recorded_id_idx ON iam_security_audit (recorded_at, id);
CREATE INDEX iam_security_audit_target_recorded_id_idx ON iam_security_audit (target_user_id, recorded_at, id);
CREATE INDEX iam_security_audit_actor_recorded_id_idx ON iam_security_audit (actor, recorded_at, id);
CREATE INDEX iam_security_audit_correlation_recorded_id_idx ON iam_security_audit (correlation_id, recorded_at, id);
