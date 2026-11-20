BEGIN;
CREATE TABLE personal_security_alerts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_hash char(64) NOT NULL UNIQUE,
    user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    device_id char(32) NOT NULL CHECK (device_id ~ '^[0-9a-f]{32}$'),
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
    signature varchar(1024) NOT NULL,
    severity smallint NOT NULL CHECK (severity BETWEEN 1 AND 255),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX personal_security_alerts_owner_time_idx ON personal_security_alerts (user_id, occurred_at DESC, id DESC);
COMMIT;
