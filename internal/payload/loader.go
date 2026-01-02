package payload

import (
	"bufio"
	"os"
	"strings"
)

// PayloadContext names
const (
	CtxHTML = "HTML"
	CtxATTR = "ATTR"
	CtxJS   = "JS"
	CtxANY  = "ANY"
)

// LoadMergedPayloads loads default payloads from the package and merges with user-provided file.
// It returns a map of context -> payload list. Context keys: HTML, ATTR, JS, ANY.
// Custom payload lines may be tagged with [HTML], [ATTR], [JS]. Untagged lines are treated as ANY.
func LoadMergedPayloads(customPath string) (map[string][]string, error) {
	result := map[string][]string{
		CtxHTML: {},
		CtxATTR: {},
		CtxJS:   {},
		CtxANY:  {},
	}

	// Load defaults from existing getters
	htmlList, _ := GetHTMLPayloadWithSize()
	attrList, _ := GetAttrPayloadWithSize()
	jsList, _ := GetInJsPayloadWithSize()
	commonList, _ := GetCommonPayloadWithSize()

	result[CtxHTML] = append(result[CtxHTML], htmlList...)
	result[CtxATTR] = append(result[CtxATTR], attrList...)
	result[CtxJS] = append(result[CtxJS], jsList...)
	result[CtxANY] = append(result[CtxANY], commonList...)

	// If no custom file provided, return
	if customPath == "" {
		return result, nil
	}

	f, err := os.Open(customPath)
	if err != nil {
		return result, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Detect tags
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "[HTML]") {
			payload := strings.TrimSpace(line[len("[HTML]"):])
			if payload != "" {
				result[CtxHTML] = append(result[CtxHTML], payload)
			}
			continue
		}
		if strings.HasPrefix(upper, "[ATTR]") {
			payload := strings.TrimSpace(line[len("[ATTR]"):])
			if payload != "" {
				result[CtxATTR] = append(result[CtxATTR], payload)
			}
			continue
		}
		if strings.HasPrefix(upper, "[JS]") {
			payload := strings.TrimSpace(line[len("[JS]"):])
			if payload != "" {
				result[CtxJS] = append(result[CtxJS], payload)
			}
			continue
		}
		// default: ANY
		result[CtxANY] = append(result[CtxANY], line)
	}

	return result, s.Err()
}
