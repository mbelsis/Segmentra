-- Usernames are unique case-insensitively (directory logins are case-insensitive; LDAP users are now
-- stored lower-cased) and a notification channel has at most one rule per event type and filter.
-- Both unique indexes are only created when the existing data has no duplicates; otherwise a NOTICE
-- names the problem and the index is skipped (resolve the duplicates and re-run the statement by hand).

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'users_username_lower_key') THEN
    RETURN;
  END IF;
  IF EXISTS (SELECT lower(username) FROM users GROUP BY lower(username) HAVING count(*) > 1) THEN
    RAISE NOTICE 'users: usernames differing only in case exist (%); unique index users_username_lower_key not created',
      (SELECT string_agg(l, ', ') FROM (SELECT lower(username) AS l FROM users GROUP BY lower(username) HAVING count(*) > 1) d);
  ELSE
    CREATE UNIQUE INDEX users_username_lower_key ON users (lower(username));
  END IF;
END
$$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'notification_rules_channel_event_filter_key') THEN
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1 FROM notification_rules
    GROUP BY channel_id, event_type, md5(coalesce(filter::text, ''))
    HAVING count(*) > 1
  ) THEN
    RAISE NOTICE 'notification_rules: duplicate (channel_id, event_type, filter) rules exist; unique index notification_rules_channel_event_filter_key not created (duplicates are still sent only once per channel)';
  ELSE
    CREATE UNIQUE INDEX notification_rules_channel_event_filter_key
      ON notification_rules (channel_id, event_type, md5(coalesce(filter::text, '')));
  END IF;
END
$$;
