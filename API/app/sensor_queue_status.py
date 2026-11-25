"""Read-only operator inspection of alerts awaiting safe attribution."""
import argparse
import json
from app.infrastructure.postgres import database


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--details', action='store_true', help='Include sensitive IP addresses and signatures')
    parser.add_argument('--limit', type=int, default=25)
    args = parser.parse_args()
    if not 1 <= args.limit <= 100:
        parser.error('--limit must be between 1 and 100')
    with database() as conn:
        count, oldest = conn.execute('SELECT count(*), min(first_received_at) FROM unattributed_sensor_alerts').fetchone()
        result = {'pending': count, 'oldest_received_at': oldest}
        if args.details:
            rows = conn.execute(
                'SELECT event_hash, occurred_at, signature, severity, source_ip, destination_ip, first_received_at, last_checked_at '
                'FROM unattributed_sensor_alerts ORDER BY first_received_at, event_hash LIMIT %s', (args.limit,),
            ).fetchall()
            keys = ('event_hash', 'occurred_at', 'signature', 'severity', 'source_ip', 'destination_ip', 'first_received_at', 'last_checked_at')
            result['events'] = [dict(zip(keys, row)) for row in rows]
    print(json.dumps(result, default=str))


if __name__ == '__main__':
    main()
