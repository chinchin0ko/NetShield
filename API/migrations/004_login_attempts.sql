BEGIN;
CREATE TABLE login_attempt_windows (
    subject_hash char(64) PRIMARY KEY,
    attempts smallint NOT NULL CHECK (attempts BETWEEN 1 AND 11),
    window_started timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_attempt_windows_started_idx ON login_attempt_windows (window_started);
COMMIT;
