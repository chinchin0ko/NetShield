BEGIN;
ALTER TABLE personal_security_alerts
    ADD COLUMN review_status varchar(20) NOT NULL DEFAULT 'new'
    CHECK (review_status IN ('new', 'reviewed', 'false_positive')),
    ADD COLUMN reviewed_at timestamptz CHECK (reviewed_at IS NULL OR isfinite(reviewed_at));
CREATE TABLE personal_alert_reviews (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alert_id bigint NOT NULL REFERENCES personal_security_alerts(id) ON DELETE CASCADE,
    user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status varchar(20) NOT NULL CHECK (status IN ('new', 'reviewed', 'false_positive')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK (isfinite(recorded_at))
);
CREATE INDEX personal_alert_reviews_owner_idx ON personal_alert_reviews (user_id, alert_id, recorded_at DESC);
COMMIT;
