"""Run periodically as the restricted API service account."""
import logging
from app.infrastructure.usage_history import collect_samples

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    count, failures = collect_samples()
    logging.info('VPN usage: %d samples, %d unavailable accounts', count, failures)
    if failures:
        raise SystemExit(1)
