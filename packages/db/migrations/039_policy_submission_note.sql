-- The reason the author gives when sending a policy version for approval; shown to the approver and written to the audit log.
ALTER TABLE policy_versions ADD COLUMN IF NOT EXISTS submission_note text;
