package api

// ArtifactIdentityResponse is the wire form of a normalized artifact identity, shared by every control-plane response
// that refers to a package or image. Version and Digest are omitted when the reference was not resolved that far, so a
// bare npm packument carries neither.
type ArtifactIdentityResponse struct {
	Ecosystem string `json:"ecosystem"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

// EvaluationReasonResponse is the wire form of one policy's contribution to a decision. Every applicable policy that
// matched is reported, not only the one that supplied the user-facing reason, so a denial can be fully explained.
type EvaluationReasonResponse struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Category   string `json:"category"`
	Action     string `json:"action"`
	Message    string `json:"message"`
}
