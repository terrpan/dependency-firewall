package workloadidentity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnrollmentProvider_AdditionalCAFileFailureIsReportedBeforeEnrollment(t *testing.T) {
	t.Parallel()
	provider := NewEnrollmentProvider(EnrollmentProviderConfig{
		PublicAPIURL:     "https://control-plane.example.com",
		AdditionalCAFile: "missing-additional-ca.pem",
	})

	_, err := provider.Acquire(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "additional CA bundle")
}
