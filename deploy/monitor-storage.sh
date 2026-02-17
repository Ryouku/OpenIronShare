#!/bin/bash
# IronShare storage monitoring
# Add to cron: */15 * * * * /opt/ironshare/monitor-storage.sh

DB_PATH="/opt/ironshare/data/ironshare.db"
MAX_DB_SIZE_MB=5000
ALERT_EMAIL="${IRONSHARE_ALERT_EMAIL:-}"

# Check if DB exists
if [ ! -f "$DB_PATH" ]; then
    exit 0
fi

# Get DB size in MB
DB_SIZE_MB=$(du -m "$DB_PATH" | cut -f1)

# Check threshold
if [ "$DB_SIZE_MB" -gt "$MAX_DB_SIZE_MB" ]; then
    echo "ALERT: IronShare DB size ($DB_SIZE_MB MB) exceeds limit ($MAX_DB_SIZE_MB MB)"

    SECRET_COUNT=$(sqlite3 -noheader "$DB_PATH" "SELECT COUNT(*) FROM secrets;")
    echo "Total secrets: $SECRET_COUNT"

    # Alert (if email configured)
    if [ -n "$ALERT_EMAIL" ]; then
        echo "IronShare DB size: $DB_SIZE_MB MB (limit: $MAX_DB_SIZE_MB MB). Secrets: $SECRET_COUNT" | \
            mail -s "IronShare Storage Alert" "$ALERT_EMAIL"
    fi

    # Step 1: Purge all expired secrets
    sqlite3 "$DB_PATH" "DELETE FROM secrets WHERE expires_at < strftime('%s', 'now');"
    PURGED_EXPIRED=$(sqlite3 -noheader "$DB_PATH" "SELECT changes();")
    echo "Purged expired: $PURGED_EXPIRED secrets"

    # Reclaim disk space from deleted rows
    sqlite3 "$DB_PATH" "VACUUM;"

    # Step 2: Re-check — if still over, progressively delete active secrets (soonest-expiring first)
    DB_SIZE_MB=$(du -m "$DB_PATH" | cut -f1)
    ROUND=0
    while [ "$DB_SIZE_MB" -gt "$MAX_DB_SIZE_MB" ]; do
        ROUND=$((ROUND + 1))
        REMAINING=$(sqlite3 -noheader "$DB_PATH" "SELECT COUNT(*) FROM secrets;")

        if [ "$REMAINING" -eq 0 ]; then
            echo "No secrets left but DB still over limit — possible SQLite bloat"
            sqlite3 "$DB_PATH" "VACUUM;"
            break
        fi

        # Delete 20% of remaining (min 1), soonest-expiring first
        TO_DELETE=$(( REMAINING / 5 ))
        [ "$TO_DELETE" -lt 1 ] && TO_DELETE=1

        sqlite3 "$DB_PATH" "DELETE FROM secrets WHERE id IN (SELECT id FROM secrets ORDER BY expires_at ASC LIMIT $TO_DELETE);"
        PURGED=$(sqlite3 -noheader "$DB_PATH" "SELECT changes();")
        echo "Round $ROUND: purged $PURGED soonest-expiring secrets ($REMAINING were remaining)"

        sqlite3 "$DB_PATH" "VACUUM;"
        DB_SIZE_MB=$(du -m "$DB_PATH" | cut -f1)

        # Safety: max 10 rounds to avoid infinite loop
        if [ "$ROUND" -ge 10 ]; then
            echo "WARNING: 10 purge rounds completed, DB still at $DB_SIZE_MB MB"
            break
        fi
    done

    echo "Final DB size: $DB_SIZE_MB MB"
fi

exit 0
