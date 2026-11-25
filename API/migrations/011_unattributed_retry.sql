BEGIN;
ALTER TABLE unattributed_sensor_alerts ADD COLUMN last_checked_at timestamptz CHECK (last_checked_at IS NULL OR isfinite(last_checked_at));
CREATE INDEX unattributed_sensor_alerts_retry_idx ON unattributed_sensor_alerts (last_checked_at ASC NULLS FIRST, first_received_at ASC);
COMMIT;
