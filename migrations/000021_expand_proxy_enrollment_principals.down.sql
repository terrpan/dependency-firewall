ALTER TABLE proxy_enrollments
    ADD COLUMN approving_principal_id TEXT,
    ADD COLUMN denying_principal_id TEXT;

UPDATE proxy_enrollments
SET approving_principal_id = approving_principal_subject
WHERE approving_principal_subject IS NOT NULL;

UPDATE proxy_enrollments
SET denying_principal_id = denying_principal_subject
WHERE denying_principal_subject IS NOT NULL;

ALTER TABLE proxy_enrollments
    DROP CONSTRAINT proxy_enrollments_approving_principal_pair_check,
    DROP CONSTRAINT proxy_enrollments_denying_principal_pair_check,
    DROP COLUMN approving_principal_issuer,
    DROP COLUMN approving_principal_subject,
    DROP COLUMN denying_principal_issuer,
    DROP COLUMN denying_principal_subject;
