BEGIN;
-- Historical intervals must never overlap for the same VPN address. The GiST
-- exclusion constraint enforces this even under concurrent transactions.
CREATE TABLE vpn_address_assignments (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    address inet NOT NULL CHECK (family(address) = 4 AND masklen(address) = 32 AND address <<= inet '10.8.0.0/24'),
    user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    device_id char(32) NOT NULL CHECK (device_id ~ '^[0-9a-f]{32}$'),
    valid_from timestamptz NOT NULL CHECK (isfinite(valid_from)),
    valid_until timestamptz CHECK (valid_until IS NULL OR (isfinite(valid_until) AND valid_until > valid_from)),
    EXCLUDE USING gist (address inet_ops WITH =, tstzrange(valid_from, valid_until, '[)') WITH &&)
);
CREATE INDEX vpn_address_assignments_user_idx ON vpn_address_assignments (user_id, device_id, valid_from DESC);
COMMIT;
