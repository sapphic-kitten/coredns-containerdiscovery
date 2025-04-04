package containerdiscovery

import (
	"fmt"
	"regexp"
)

func validateLabel(label string) error {
	if len(label) < 3 || len(label) > 30 {
		return ErrLabelLength
	}

	pattern := regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	if !pattern.MatchString(label) {
		return ErrLabelInvalidCharacter
	}

	return nil
}

func buildLabel(label, suffix string) string {
	return fmt.Sprintf("%s.%s", label, suffix)
}

func buildLabelWithValue(label, suffix, value string) string {
	return fmt.Sprintf("%s=%s", buildLabel(label, suffix), value)
}
