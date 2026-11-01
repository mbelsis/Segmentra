-- Normalize IoT asset addresses and MACs stored before input validation (idempotent, never fails).
--
-- ip_address: a value with host bits set (192.168.10.5/24, as `ip addr` prints it) always meant the
-- single device; a full-length prefix (/32, /128) is the same host. Both become the bare host address,
-- so they can no longer compile as the whole network. True network CIDRs (192.168.10.0/24) are kept.
-- mac_address: any separator style (AA-BB-CC-DD-EE-FF, aabb.ccdd.eeff) becomes aa:bb:cc:dd:ee:ff.
-- Values that are not valid inet text / not 12 hex digits are left untouched.
DO $$
DECLARE
  r record;
  addr inet;
  hex text;
BEGIN
  IF to_regclass('public.iot_assets') IS NULL THEN
    RETURN;
  END IF;

  FOR r IN
    SELECT id, ip_address FROM iot_assets
     WHERE ip_address IS NOT NULL AND btrim(ip_address) ~ '^[0-9A-Fa-f.:]+/[0-9]{1,3}$'
  LOOP
    BEGIN
      addr := btrim(r.ip_address)::inet;
    EXCEPTION WHEN others THEN
      CONTINUE;
    END;
    -- (no CASE inside the IF condition: PL/pgSQL ends the condition at the first THEN)
    IF masklen(addr) = 32 AND family(addr) = 4 OR masklen(addr) = 128
       OR host(addr) <> host(network(addr)) THEN
      UPDATE iot_assets SET ip_address = host(addr), updated_at = now() WHERE id = r.id;
    END IF;
  END LOOP;

  FOR r IN SELECT id, mac_address FROM iot_assets WHERE mac_address IS NOT NULL LOOP
    hex := regexp_replace(lower(r.mac_address), '[^0-9a-f]', '', 'g');
    IF length(hex) = 12 AND lower(r.mac_address) ~ '^[0-9a-f:. -]+$' THEN
      hex := substr(hex, 1, 2) || ':' || substr(hex, 3, 2) || ':' || substr(hex, 5, 2) || ':' ||
             substr(hex, 7, 2) || ':' || substr(hex, 9, 2) || ':' || substr(hex, 11, 2);
      IF hex <> r.mac_address THEN
        UPDATE iot_assets SET mac_address = hex, updated_at = now() WHERE id = r.id;
      END IF;
    END IF;
  END LOOP;
END
$$;
