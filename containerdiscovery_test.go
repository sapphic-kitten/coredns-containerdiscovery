package containerdiscovery

import (
	"testing"
)

func TestValidLabel(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		label  string
		result error
	}{
		{"valid.label", nil},
		{"valid_label", nil},
		{"invalid label with spaces", ErrLabelInvalidCharacter},
		{"sh", ErrLabelLength},
		{"a.very.very.long.label.1234567890", ErrLabelLength},
	}

	for _, test := range tests {
		t.Run(test.label, func(t *testing.T) {
			t.Parallel()
			if err := validateLabel(test.label); err != test.result {
				t.Fatalf("Expected %q, got %q", test.result, err)
			}
		})
	}
}
