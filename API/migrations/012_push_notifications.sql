BEGIN;
CREATE TABLE push_subscriptions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id char(32) NOT NULL CHECK (device_id ~ '^[0-9a-f]{32}$'),
    token varchar(4096) NOT NULL UNIQUE,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(user_id, device_id)
);
CREATE TABLE push_outbox (
    alert_id bigint NOT NULL REFERENCES personal_security_alerts(id) ON DELETE CASCADE,
    subscription_id bigint NOT NULL REFERENCES push_subscriptions(id) ON DELETE CASCADE,
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(alert_id, subscription_id)
);
CREATE INDEX push_outbox_pending_idx ON push_outbox(next_attempt_at);
CREATE FUNCTION queue_personal_alert_push() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO push_outbox (alert_id, subscription_id)
    SELECT NEW.id, id FROM push_subscriptions WHERE user_id = NEW.user_id;
    RETURN NEW;
END;
$$;
CREATE TRIGGER personal_alert_push AFTER INSERT ON personal_security_alerts
FOR EACH ROW EXECUTE FUNCTION queue_personal_alert_push();
COMMIT;
