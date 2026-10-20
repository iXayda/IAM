CREATE TABLE iam_refresh_family (
    authorization_id varchar(100) PRIMARY KEY REFERENCES iam_authorization_binding(authorization_id),
    version BIGINT NOT NULL CHECK (version >= 1),
    generation BIGINT NOT NULL CHECK (generation >= 0),
    current_digest char(64) NOT NULL UNIQUE CHECK (current_digest ~ '^[0-9a-f]{64}$'),
    scopes varchar(64) NOT NULL CHECK (scopes IN ('openid','profile','offline_access','openid,profile','offline_access,openid','offline_access,profile','offline_access,openid,profile')),
    started_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    status varchar(16) NOT NULL CHECK (status IN ('active','closed','quarantined','revoked')),
    CHECK (isfinite(started_at) AND isfinite(updated_at) AND isfinite(idle_expires_at) AND isfinite(absolute_expires_at)
        AND started_at <= updated_at AND started_at < idle_expires_at AND idle_expires_at <= absolute_expires_at
        AND idle_expires_at <= updated_at + INTERVAL '604800 seconds' AND absolute_expires_at <= started_at + INTERVAL '2592000 seconds'),
    CHECK (status <> 'active' OR (idle_expires_at > updated_at AND 'offline_access'=ANY(string_to_array(scopes,',')))),
    CHECK (status <> 'closed' OR NOT ('offline_access'=ANY(string_to_array(scopes,','))))
);

CREATE TABLE iam_refresh_history (
    digest char(64) PRIMARY KEY CHECK (digest ~ '^[0-9a-f]{64}$'),
    authorization_id varchar(100) NOT NULL REFERENCES iam_refresh_family(authorization_id),
    generation BIGINT NOT NULL CHECK (generation >= 0),
    parent_digest char(64) UNIQUE CHECK (parent_digest ~ '^[0-9a-f]{64}$' AND parent_digest <> digest),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    seal char(64) NOT NULL CHECK (seal ~ '^[0-9a-f]{64}$'),
    UNIQUE (authorization_id,generation),
    UNIQUE (authorization_id,digest),
    UNIQUE (authorization_id,digest,generation),
    FOREIGN KEY (authorization_id,parent_digest) REFERENCES iam_refresh_history(authorization_id,digest),
    CHECK ((generation=0)=(parent_digest IS NULL)),
    CHECK (isfinite(issued_at) AND isfinite(expires_at) AND issued_at < expires_at
        AND (consumed_at IS NULL OR (isfinite(consumed_at) AND issued_at <= consumed_at AND consumed_at < expires_at)))
);
ALTER TABLE iam_refresh_family ADD CONSTRAINT iam_refresh_family_current
    FOREIGN KEY (authorization_id,current_digest,generation) REFERENCES iam_refresh_history(authorization_id,digest,generation)
    DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX iam_refresh_family_expiry_idx ON iam_refresh_family(absolute_expires_at,authorization_id);

CREATE FUNCTION iam_initialize_refresh_family() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.version <> 1 OR NEW.generation <> 0 OR NEW.status <> 'active' OR NOT EXISTS (
        SELECT 1 FROM iam_authorization_binding b WHERE b.authorization_id=NEW.authorization_id
            AND b.scopes=NEW.scopes AND b.issued_at <= NEW.started_at AND NEW.started_at < b.code_expires_at
            AND NEW.absolute_expires_at=b.issued_at + INTERVAL '2592000 seconds'
    ) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='initial refresh family does not match original bounds';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER iam_refresh_family_initialization BEFORE INSERT ON iam_refresh_family
    FOR EACH ROW EXECUTE FUNCTION iam_initialize_refresh_family();

CREATE FUNCTION iam_initialize_refresh_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.consumed_at IS NOT NULL OR NEW.expires_at > NEW.issued_at + INTERVAL '604800 seconds' OR NOT EXISTS (
        SELECT 1 FROM iam_refresh_family f WHERE f.authorization_id=NEW.authorization_id
            AND f.started_at <= NEW.issued_at AND NEW.expires_at <= f.absolute_expires_at
            AND (NEW.generation <> 0 OR (f.generation=0 AND f.current_digest=NEW.digest
                AND f.started_at=NEW.issued_at AND f.idle_expires_at=NEW.expires_at))
    ) OR (NEW.parent_digest IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM iam_refresh_history h WHERE h.authorization_id=NEW.authorization_id AND h.digest=NEW.parent_digest
            AND h.generation=NEW.generation-1 AND h.consumed_at IS NOT NULL AND h.issued_at <= NEW.issued_at AND NEW.issued_at < h.expires_at
    )) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='refresh history successor does not match its parent and bounds';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER iam_refresh_history_initialization BEFORE INSERT ON iam_refresh_history
    FOR EACH ROW EXECUTE FUNCTION iam_initialize_refresh_history();

CREATE FUNCTION iam_protect_refresh_family() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        IF clock_timestamp() <= OLD.absolute_expires_at + INTERVAL '330 seconds' THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='refresh replay detection window has not ended';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.authorization_id <> OLD.authorization_id OR NEW.started_at <> OLD.started_at OR NEW.absolute_expires_at <> OLD.absolute_expires_at
        OR NEW.version <> OLD.version+1 OR NEW.updated_at < OLD.updated_at
        OR NOT (string_to_array(NEW.scopes,',') <@ string_to_array(OLD.scopes,','))
        OR NEW.generation NOT IN (OLD.generation,OLD.generation+1)
        OR (OLD.status <> 'active' AND (NEW.status='active' OR NEW.generation <> OLD.generation))
        OR (NEW.generation=OLD.generation AND (NEW.current_digest <> OLD.current_digest OR NEW.scopes <> OLD.scopes OR NEW.idle_expires_at <> OLD.idle_expires_at))
        OR (NEW.generation=OLD.generation+1 AND (OLD.status <> 'active' OR NEW.current_digest=OLD.current_digest OR NEW.status NOT IN ('active','closed')))
        OR (OLD.status IN ('quarantined','revoked') AND NEW.status NOT IN ('quarantined','revoked')) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='refresh family transition is invalid';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER iam_refresh_family_protection BEFORE UPDATE OR DELETE ON iam_refresh_family
    FOR EACH ROW EXECUTE FUNCTION iam_protect_refresh_family();

CREATE FUNCTION iam_protect_refresh_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        IF EXISTS (SELECT 1 FROM iam_refresh_family WHERE authorization_id=OLD.authorization_id
            AND clock_timestamp() <= absolute_expires_at + INTERVAL '330 seconds') THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='refresh replay detection window has not ended';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.digest <> OLD.digest OR NEW.authorization_id <> OLD.authorization_id OR NEW.generation <> OLD.generation
        OR NEW.parent_digest IS DISTINCT FROM OLD.parent_digest OR NEW.issued_at <> OLD.issued_at OR NEW.expires_at <> OLD.expires_at
        OR OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL OR NEW.seal=OLD.seal THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='refresh history only allows its first spent transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER iam_refresh_history_protection BEFORE UPDATE OR DELETE ON iam_refresh_history
    FOR EACH ROW EXECUTE FUNCTION iam_protect_refresh_history();
