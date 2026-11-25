BEGIN;
CREATE TABLE vpn_sensor_heartbeat (
    id smallint PRIMARY KEY CHECK (id = 1),
    last_seen timestamptz NOT NULL
);
COMMIT;
