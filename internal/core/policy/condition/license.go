package condition

import (
	"fmt"
	"strings"

	"github.com/danielterry/dependency-firewall/internal/core/domain"
)

// License matches when any declared artifact license matches the configured list.
type License struct{}

// LicenseAllowlist matches when an artifact is missing license metadata or
// declares a license outside the configured approved set.
type LicenseAllowlist struct{}

// Evaluate checks whether the artifact metadata contains a configured license identifier.
func (l License) Evaluate(req domain.AccessRequest, config domain.PolicyConfig) (bool, string, error) {
	typed, ok := config.(*domain.LicensePolicyConfig)
	if !ok {
		return false, "", fmt.Errorf("license requires %T, got %T", &domain.LicensePolicyConfig{}, config)
	}
	if err := typed.Validate(); err != nil {
		return false, "", err
	}

	if req.Metadata == nil || len(req.Metadata.Licenses) == 0 {
		return false, "", nil
	}

	allowed := approvedLicenses(typed.Licenses)

	for _, license := range req.Metadata.Licenses {
		if _, ok := allowed[licenseKey(license)]; ok {
			return true, fmt.Sprintf("license %q matched policy", license), nil
		}
	}

	return false, "", nil
}

// Evaluate checks whether the artifact license set violates the approved list.
func (l LicenseAllowlist) Evaluate(req domain.AccessRequest, config domain.PolicyConfig) (bool, string, error) {
	if isUnversionedNPMMetadataRequest(req) {
		return false, "", nil
	}

	licenses, unlicensedBehavior, unavailableBehavior, err := licenseAllowlistSettings(config)
	if err != nil {
		return false, "", err
	}

	if req.Metadata == nil {
		matched, reason := applyMissingLicenseBehavior(
			unavailableBehavior,
			licenseMetadataUnavailableReason(req.Artifact),
		)
		return matched, reason, nil
	}

	if len(req.Metadata.Licenses) == 0 {
		matched, reason := applyMissingLicenseBehavior(unlicensedBehavior, unlicensedArtifactReason(req.Artifact))
		return matched, reason, nil
	}

	allowed := approvedLicenses(licenses)
	for _, license := range req.Metadata.Licenses {
		if _, ok := allowed[licenseKey(license)]; !ok {
			return true, fmt.Sprintf("license %q is not in the approved license list", license), nil
		}
	}

	return false, "", nil
}

func licenseAllowlistSettings(
	config domain.PolicyConfig,
) ([]string, domain.LicenseAllowlistMissingBehavior, domain.LicenseAllowlistMissingBehavior, error) {
	switch typed := config.(type) {
	case *domain.LicenseAllowlistPolicyConfig:
		if err := typed.Validate(); err != nil {
			return nil, "", "", err
		}
		return typed.Licenses,
			domain.LicenseAllowlistMissingBehaviorDeny,
			domain.LicenseAllowlistMissingBehaviorDeny,
			nil
	case *domain.LicenseAllowlistPolicyConfigV2:
		if err := typed.Validate(); err != nil {
			return nil, "", "", err
		}
		return typed.Licenses,
			typed.EffectiveUnlicensedBehavior(),
			typed.EffectiveUnavailableMetadataBehavior(),
			nil
	default:
		return nil, "", "", fmt.Errorf(
			"license_allowlist requires %T or %T, got %T",
			&domain.LicenseAllowlistPolicyConfig{},
			&domain.LicenseAllowlistPolicyConfigV2{},
			config,
		)
	}
}

func approvedLicenses(licenses []string) map[string]struct{} {
	allowed := make(map[string]struct{}, len(licenses))
	for _, license := range licenses {
		allowed[licenseKey(license)] = struct{}{}
	}
	return allowed
}

func licenseKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func isUnversionedNPMMetadataRequest(req domain.AccessRequest) bool {
	return req.Artifact.Ecosystem == domain.EcosystemNPM && strings.TrimSpace(req.Artifact.Version) == ""
}

func applyMissingLicenseBehavior(
	behavior domain.LicenseAllowlistMissingBehavior,
	reason string,
) (bool, string) {
	if behavior == domain.LicenseAllowlistMissingBehaviorSkip {
		return false, ""
	}

	return true, reason
}

func licenseMetadataUnavailableReason(artifact domain.ArtifactIdentity) string {
	ref := artifactLicenseReference(artifact)
	if ref == "" {
		return "license metadata is unavailable and approved-license policy denies the artifact"
	}

	return fmt.Sprintf("license metadata is unavailable for %s and approved-license policy denies the artifact", ref)
}

func unlicensedArtifactReason(artifact domain.ArtifactIdentity) string {
	ref := artifactLicenseReference(artifact)
	if ref == "" {
		return "artifact does not declare a license and approved-license policy denies the artifact"
	}

	return fmt.Sprintf("artifact %s does not declare a license and approved-license policy denies the artifact", ref)
}

func artifactLicenseReference(artifact domain.ArtifactIdentity) string {
	ref := artifact.FullName()
	switch {
	case strings.TrimSpace(artifact.Digest) != "":
		ref += "@" + strings.TrimSpace(artifact.Digest)
	case strings.TrimSpace(artifact.Version) != "":
		ref += "@" + strings.TrimSpace(artifact.Version)
	}
	return ref
}
