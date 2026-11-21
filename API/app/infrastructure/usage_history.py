"""Bounded, account-scoped samples of VPN counters; not billing records."""
from app.infrastructure.postgres import database


def collect_samples():
    """Sample enabled peers; one collector at a time, without exposing keys."""
    from app.infrastructure.wg_easy_bridge import device_usage, ProvisioningError
    failures = 0
    with database() as lock:
        if not lock.execute('SELECT pg_try_advisory_lock(%s, %s)', (19112, 1)).fetchone()[0]:
            return 0, 0
        try:
            users = lock.execute('SELECT DISTINCT user_id FROM vpn_address_assignments WHERE valid_until IS NULL').fetchall()
            count = 0
            for (user_id,) in users:
                try:
                    devices = device_usage(user_id)
                except ProvisioningError:
                    failures += 1
                    continue
                with database() as conn:
                    for item in devices:
                        up, down = item['upload_bytes'], item['download_bytes']
                        if up is None or down is None:
                            continue
                        conn.execute('INSERT INTO vpn_usage_samples (user_id, device_id, upload_bytes, download_bytes) VALUES (%s, %s, %s, %s)',
                                     (user_id, item['device_id'], up, down))
                        count += 1
            with database() as conn:
                conn.execute("DELETE FROM vpn_usage_samples WHERE sampled_at < clock_timestamp() - interval '30 days'")
            return count, failures
        finally:
            lock.execute('SELECT pg_advisory_unlock(%s, %s)', (19112, 1))


def history_for_user(user_id):
    if type(user_id) is not int or user_id <= 0:
        raise ValueError('invalid user')
    # Include the previous day's sample in the window; never bridge long gaps
    # or a visible counter reset. Assign each interval to the end date in UTC.
    with database() as conn:
        rows = conn.execute('''
            WITH ordered AS (
                SELECT device_id, sampled_at, upload_bytes, download_bytes,
                       lag(sampled_at) OVER w AS previous_at,
                       lag(upload_bytes) OVER w AS previous_up,
                       lag(download_bytes) OVER w AS previous_down
                FROM vpn_usage_samples
                WHERE user_id = %s AND sampled_at >= clock_timestamp() - interval '8 days'
                WINDOW w AS (PARTITION BY device_id ORDER BY sampled_at, id)
            ), intervals AS (
                SELECT *, previous_at IS NOT NULL
                    AND sampled_at - previous_at <= interval '30 minutes'
                    AND upload_bytes >= previous_up AND download_bytes >= previous_down AS complete
                FROM ordered
            )
            SELECT device_id, (sampled_at AT TIME ZONE 'UTC')::date AS day,
                   sum(CASE WHEN complete THEN upload_bytes - previous_up END),
                   sum(CASE WHEN complete THEN download_bytes - previous_down END),
                   bool_or(NOT complete), max(sampled_at)
            FROM intervals WHERE sampled_at >= clock_timestamp() - interval '7 days'
            GROUP BY device_id, day ORDER BY day DESC, device_id
        ''', (user_id,)).fetchall()
    return [{'device_id': d, 'day': day, 'upload_bytes': up, 'download_bytes': down,
             'incomplete': incomplete, 'last_sample_at': last} for d, day, up, down, incomplete, last in rows]
