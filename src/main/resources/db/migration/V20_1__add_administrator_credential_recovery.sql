ALTER TABLE iam_administrator_recovery DROP CONSTRAINT iam_administrator_recovery_source;
ALTER TABLE iam_administrator_recovery ADD CONSTRAINT iam_administrator_recovery_source CHECK (
    source ~ '^deployment:(admin-recovery|admin-credentials):[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}$'
);
