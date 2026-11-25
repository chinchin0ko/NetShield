BEGIN;
CREATE TABLE security_alerts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_hash char(64) NOT NULL UNIQUE,
    occurred_at timestamptz NOT NULL,
    signature varchar(1024) NOT NULL,
    severity smallint NOT NULL CHECK (severity BETWEEN 1 AND 255),
    source_ip inet,
    destination_ip inet,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX security_alerts_occurred_at_idx ON security_alerts (occurred_at DESC);
COMMIT;
