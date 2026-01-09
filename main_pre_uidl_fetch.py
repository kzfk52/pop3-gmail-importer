#!/usr/bin/env python3
"""
POP3 UIDL Fetcher
Fetches UIDL list from POP3 server and saves them as processed
Version: 1.0
"""

import os
import ssl
import json
import logging
import poplib
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from dotenv import load_dotenv


def setup_logging():
    """Setup logging configuration"""
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    log_file = os.getenv('LOG_FILE', 'logs/pop3_uidl_fetcher.log')
    log_max_bytes = int(os.getenv('LOG_MAX_BYTES', 10485760))  # 10MB
    log_backup_count = int(os.getenv('LOG_BACKUP_COUNT', 5))

    # Create logs directory
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, mode=0o700)

    # Configure logging
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level))

    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=log_max_bytes,
        backupCount=log_backup_count
    )
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('%(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    logging.info("Logging initialized (UIDL Fetcher v1.0)")


def mask_email(email):
    """Partially mask email address for log output"""
    if not email or '@' not in email:
        return email
    parts = email.split('@')
    return f"{parts[0][:1]}***@{parts[1]}"


def get_env_bool(key, default=True):
    """Get boolean value from environment variable"""
    value = os.getenv(key, str(default)).lower()
    return value in ('true', '1', 'yes', 'on')


def get_env_int(key, default):
    """Get integer value from environment variable"""
    try:
        return int(os.getenv(key, default))
    except ValueError:
        return default

def connect_pop3(account_num, config):
    """Connect to POP3 server"""
    host = config['pop3_host']
    port = config['pop3_port']
    use_ssl = config['pop3_use_ssl']
    verify_cert = config['pop3_verify_cert']
    username = config['pop3_username']
    password = config['pop3_password']

    logging.info(f"Account {account_num}: Connecting to POP3 {host}:{port} (SSL: {use_ssl})")

    try:
        if use_ssl:
            # Create SSL context
            context = ssl.create_default_context()
            if not verify_cert:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                logging.warning(f"Account {account_num}: TLS certificate verification disabled")

            pop3 = poplib.POP3_SSL(host, port, context=context, timeout=30)
        else:
            pop3 = poplib.POP3(host, port, timeout=30)

        # Authenticate
        pop3.user(username)
        pop3.pass_(password)

        logging.info(f"Account {account_num}: POP3 authentication successful (user: {mask_email(username)})")
        return pop3

    except Exception as e:
        logging.error(f"Account {account_num}: POP3 connection failed: {e}")
        return None


def load_uidl_state(account_num, state_dir):
    """Load UIDL state from file"""
    state_file = Path(state_dir) / f"account{account_num}_uidl.jsonl"
    state = {}

    if state_file.exists():
        try:
            with open(state_file, 'r') as f:
                for line in f:
                    if line.strip():
                        record = json.loads(line)
                        state[record['uidl']] = record
            logging.debug(f"Account {account_num}: Loaded {len(state)} UIDL records")
        except Exception as e:
            logging.error(f"Account {account_num}: Failed to load UIDL state: {e}")

    return state


def save_uidl_record(account_num, state_dir, uidl):
    """Append UIDL record to state file"""
    state_file = Path(state_dir) / f"account{account_num}_uidl.jsonl"

    # Create state directory
    state_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    record = {
        'uidl': uidl,
        'timestamp': datetime.now().isoformat()
    }

    try:
        with open(state_file, 'a') as f:
            f.write(json.dumps(record) + '\n')
        os.chmod(state_file, 0o600)
        logging.debug(f"Account {account_num}: UIDL record saved: {uidl[:20]}...")
        return True
    except Exception as e:
        logging.error(f"Account {account_num}: Failed to save UIDL record: {e}")
        return False


def cleanup_old_uidl_records(account_num, state_dir, retention_days):
    """Remove UIDL records older than retention_days"""
    state_file = Path(state_dir) / f"account{account_num}_uidl.jsonl"

    if not state_file.exists():
        return

    cutoff_date = datetime.now() - timedelta(days=retention_days)
    kept_records = []
    removed_count = 0

    try:
        with open(state_file, 'r') as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    record_date = datetime.fromisoformat(record['timestamp'])
                    if record_date >= cutoff_date:
                        kept_records.append(line)
                    else:
                        removed_count += 1

        # Rewrite file with kept records
        with open(state_file, 'w') as f:
            f.writelines(kept_records)
        os.chmod(state_file, 0o600)

        if removed_count > 0:
            logging.info(f"Account {account_num}: Cleaned up {removed_count} old UIDL records (>{retention_days} days)")
    except Exception as e:
        logging.error(f"Account {account_num}: Failed to cleanup UIDL records: {e}")


def process_account(account_num):
    """Fetch UIDL list for one account and save as processed"""
    prefix = f"ACCOUNT{account_num}_"

    # Check if account is enabled
    if not get_env_bool(f"{prefix}ENABLED", False):
        logging.debug(f"Account {account_num}: Skipped (disabled)")
        return

    logging.info(f"Account {account_num}: Processing started")

    # Load configuration
    config = {
        'pop3_host': os.getenv(f"{prefix}POP3_HOST"),
        'pop3_port': get_env_int(f"{prefix}POP3_PORT", 995),
        'pop3_use_ssl': get_env_bool(f"{prefix}POP3_USE_SSL", True),
        'pop3_verify_cert': get_env_bool(f"{prefix}POP3_VERIFY_CERT", True),
        'pop3_username': os.getenv(f"{prefix}POP3_USERNAME"),
        'pop3_password': os.getenv(f"{prefix}POP3_PASSWORD"),
        'uidl_retention_days': get_env_int(f"{prefix}UIDL_RETENTION_DAYS", 90)
    }

    # Validate required settings
    required = ['pop3_host', 'pop3_username', 'pop3_password']
    for key in required:
        if not config[key]:
            logging.error(f"Account {account_num}: Missing required setting: {key}")
            return

    # Connect to POP3
    pop3 = connect_pop3(account_num, config)
    if not pop3:
        return

    try:
        # Get message count
        num_messages = len(pop3.list()[1])
        logging.info(f"Account {account_num}: {num_messages} messages on server")

        if num_messages == 0:
            pop3.quit()
            logging.info(f"Account {account_num}: No messages on server")
            return

        # Get UIDL list
        uidl_response = pop3.uidl()
        uidl_list = []
        for item in uidl_response[1]:
            parts = item.decode('utf-8').split()
            uidl = parts[1]
            uidl_list.append(uidl)

        logging.info(f"Account {account_num}: Retrieved {len(uidl_list)} UIDLs from server")

        # Close POP3 connection
        pop3.quit()
        logging.info(f"Account {account_num}: POP3 session closed")

        # Save all UIDLs as processed
        state_dir = 'state'
        saved_count = 0
        for uidl in uidl_list:
            if save_uidl_record(account_num, state_dir, uidl):
                saved_count += 1

        logging.info(f"Account {account_num}: Saved {saved_count} UIDL records")

        # Cleanup old UIDL records
        cleanup_old_uidl_records(account_num, state_dir, config['uidl_retention_days'])

        logging.info(f"Account {account_num}: Processing completed")

    except Exception as e:
        import traceback
        logging.error(f"Account {account_num}: Unexpected error: {e}")
        logging.error(f"Account {account_num}: Traceback:\n{traceback.format_exc()}")
        try:
            pop3.quit()
        except:
            pass


def main():
    """Main program"""
    # Load environment variables
    load_dotenv()

    # Setup logging
    setup_logging()

    try:
        # Get configuration
        account_count = get_env_int('ACCOUNT_COUNT', 1)

        logging.info(f"POP3 UIDL Fetcher v1.0 started")
        logging.info(f"Accounts to process: {account_count}")

        # Process each account
        for account_num in range(1, account_count + 1):
            process_account(account_num)

        logging.info("All accounts processed")

    except Exception as e:
        logging.error(f"Fatal error: {e}")
        raise


if __name__ == '__main__':
    main()
