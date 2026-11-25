BEGIN;
-- Restricted operational holding area; never exposed as a user's alerts.
CREATE TABLE unattributed_sensor_alerts (
    event_hash char(64) PRIMARY KEY,
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
    signature varchar(1024) NOT NULL,
    severity smallint NOT NULL CHECK (severity BETWEEN 1 AND 255),
    source_ip inet,
    destination_ip inet,
    first_received_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX unattributed_sensor_alerts_received_idx ON unattributed_sensor_alerts (first_received_at);
COMMIT;
