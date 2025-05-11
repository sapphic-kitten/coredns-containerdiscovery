package containerdiscovery

import (
	"fmt"
	"strings"
)

type labelType string

const (
	Network labelType = "network"
	Domain  labelType = "domain"
	A       labelType = "a"
	AAAA    labelType = "aaaa"
	CNAME   labelType = "cname"
	TXT     labelType = "txt"
)

var labelNameMap = map[string]labelType{
	"network": Network,
	"domain":  Domain,
	"a":       A,
	"aaaa":    AAAA,
	"cname":   CNAME,
	"txt":     TXT,
}

type Label struct {
	Type  labelType
	Value string
}

func parseLabels(labels map[string]string, prefix string) (map[string][]Label, error) {
	parsed := make(map[string][]Label)

	for fullLabel, value := range labels {
		fullLabel = strings.ToLower(fullLabel)

		if label, ok := strings.CutPrefix(fullLabel, fmt.Sprintf("%s.", prefix)); ok {
			split := strings.SplitN(label, ".", 2)
			if len(split) != 2 {
				return nil, NewMalformedLabelError(fullLabel)
			}

			name := split[0]
			Type, ok := labelNameMap[split[1]]
			if !ok {
				return nil, NewUnknownLabelError(fullLabel)
			}

			parsed[name] = append(parsed[name], Label{Type, value})
		}
	}
	return parsed, nil
}
