-- Session revocation: every JWT carries the user's id (uid) and token_version (tv). requireAuth rejects a
-- token whose tv no longer matches, so bumping token_version (password change, admin password reset,
-- logout) invalidates all of that user's existing sessions. Tokens of a deleted and re-created user do
-- not match the new user's id.
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version integer NOT NULL DEFAULT 0;
