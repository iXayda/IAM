-- Pin the deployment key before any authorization or interactive protocol state is created.
CREATE TABLE iam_authorization_protection (
    singleton SMALLINT PRIMARY KEY CHECK (singleton = 1),
    key_id VARCHAR(64),
    CONSTRAINT iam_authorization_protection_key CHECK (key_id IS NULL OR key_id ~ '^[0-9a-f]{64}$')
);
INSERT INTO iam_authorization_protection(singleton) VALUES (1);
