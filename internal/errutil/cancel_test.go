package errutil

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsDeadlineExceeded(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "deadline exceeded",
			err:  context.DeadlineExceeded,
			want: true,
		},
		{
			name: "wrapped deadline exceeded",
			err:  fmt.Errorf("querying database: %w", context.DeadlineExceeded),
			want: true,
		},
		{
			name: "canceled is not deadline exceeded",
			err:  context.Canceled,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsDeadlineExceeded(tt.err))
		})
	}
}

func TestIsDeadlineExceededContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	assert.True(t, IsDeadlineExceededContext(ctx))
	assert.False(t, IsDeadlineExceededContext(context.Background()))
	assert.False(t, IsDeadlineExceededContext(nil))
}
