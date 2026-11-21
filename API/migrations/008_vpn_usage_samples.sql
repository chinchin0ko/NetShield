BEGIN;
-- Raw counters are retained briefly so resets and gaps can be reported honestly.
CREATE TABLE vpn_usage_samples (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id char(32) NOT NULL CHECK (device_id ~ '^[0-9a-f]{32}$'),
    sampled_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK (isfinite(sampled_at)),
    upload_bytes bigint NOT NULL CHECK (upload_bytes >= 0),
    download_bytes bigint NOT NULL CHECK (download_bytes >= 0)
);
CREATE INDEX vpn_usage_samples_user_device_time_idx ON vpn_usage_samples (user_id, device_id, sampled_at DESC, id DESC);
CREATE INDEX vpn_usage_samples_time_idx ON vpn_usage_samples (sampled_at);
COMMIT;
