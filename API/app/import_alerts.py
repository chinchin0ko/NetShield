"""Import newline-delimited Suricata EVE events from stdin, without tailing a live file."""
import sys
from app.application.alerts import AlertService, InvalidAlert
from app.infrastructure.alerts import PostgresAlerts


def main():
    service = AlertService(PostgresAlerts())
    inserted = skipped = invalid = 0
    for line in sys.stdin:
        try:
            if service.ingest(line):
                inserted += 1
            else:
                skipped += 1
        except InvalidAlert:
            invalid += 1
    print(f'inserted={inserted} skipped={skipped} invalid={invalid}', file=sys.stderr)
    return 1 if invalid else 0


if __name__ == '__main__':
    sys.exit(main())
