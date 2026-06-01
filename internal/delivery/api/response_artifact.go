package api

type ArtifactIdentityResponse struct {
	Ecosystem string `json:"ecosystem"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

type EvaluationReasonResponse struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Category   string `json:"category"`
	Action     string `json:"action"`
	Message    string `json:"message"`
}
