BEGIN;
CREATE TABLE devices (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name varchar(100) NOT NULL,
    public_key varchar(44) NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX devices_user_id_idx ON devices (user_id);
COMMIT;
