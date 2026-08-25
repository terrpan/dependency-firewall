ALTER TABLE proxy_enrollments
    ADD COLUMN approving_principal_issuer TEXT,
    ADD COLUMN approving_principal_subject TEXT,
    ADD COLUMN denying_principal_issuer TEXT,
    ADD COLUMN denying_principal_subject TEXT;

UPDATE proxy_enrollments
SET approving_principal_issuer = 'urn:dependency-firewall:legacy-principal-id',
    approving_principal_subject = approving_principal_id
WHERE approving_principal_id IS NOT NULL;

UPDATE proxy_enrollments
SET denying_principal_issuer = 'urn:dependency-firewall:legacy-principal-id',
    denying_principal_subject = denying_principal_id
WHERE denying_principal_id IS NOT NULL;

ALTER TABLE proxy_enrollments
    DROP COLUMN approving_principal_id,
    DROP COLUMN denying_principal_id,
    ADD CONSTRAINT proxy_enrollments_approving_principal_pair_check
        CHECK ((approving_principal_issuer IS NULL) = (approving_principal_subject IS NULL)),
    ADD CONSTRAINT proxy_enrollments_denying_principal_pair_check
        CHECK ((denying_principal_issuer IS NULL) = (denying_principal_subject IS NULL));
