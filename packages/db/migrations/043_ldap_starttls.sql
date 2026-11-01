-- LDAP StartTLS (ldap:// upgraded to TLS before binding). The CA certificate used to verify the directory
-- is stored encrypted in secret_store and referenced by the existing ldap_settings.tls_ca_cert_secret_id.
ALTER TABLE ldap_settings ADD COLUMN IF NOT EXISTS start_tls boolean NOT NULL DEFAULT false;
