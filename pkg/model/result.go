package model

import (
	"time"
)

// PoC is PoC struct for Result
type PoC struct {
	Type            string `json:"type"`
	InjectType      string `json:"inject_type"`
	PoCType         string `json:"poc_type"`
	Method          string `json:"method"`
	Data            string `json:"data"`
	Param           string `json:"param"`
	Payload         string `json:"payload"`
	Evidence        string `json:"evidence"`
	CWE             string `json:"cwe"`
	Severity        string `json:"severity"`
	MessageID       int64  `json:"message_id,omitempty"`
	MessageStr      string `json:"message_str,omitempty"`
	RawHTTPRequest  string `json:"raw_request,omitempty"`
	RawHTTPResponse string `json:"raw_response,omitempty"`

	// Browser Validation (NEW)
	BrowserValidated    bool     `json:"browser_validated,omitempty"`
	ExecutionDetected   bool     `json:"execution_detected,omitempty"`
	ExecutionType       string   `json:"execution_type,omitempty"`    // "alert", "confirm", "prompt", "dom-change", "stored"
	ExecutionContext    string   `json:"execution_context,omitempty"` // "html", "attribute", "javascript"
	ScreenshotPath      string   `json:"screenshot_path,omitempty"`   // Only if execution confirmed
	ScreenshotBase64    string   `json:"screenshot_base64,omitempty"` // Only if execution confirmed
	JSConsoleLogs       []string `json:"js_console_logs,omitempty"`
	JSConsoleErrors     []string `json:"js_console_errors,omitempty"`
	ValidationTimestamp int64    `json:"validation_timestamp,omitempty"`

	// BeEF Hook Information (NEW)
	BeEFHookID     string `json:"beef_hook_id,omitempty"`
	BeEFHookActive bool   `json:"beef_hook_active,omitempty"`
	BeEFHookCount  int    `json:"beef_hook_count,omitempty"` // Number of browsers hooked
}

// Result is struct for library and cli application
type Result struct {
	Logs      []string      `json:"logs"`
	PoCs      []PoC         `json:"pocs"`
	Params    []ParamResult `json:"params"`
	Duration  time.Duration `json:"duration"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
}

type ParamResult struct {
	Name           string
	Type           string
	Reflected      bool
	ReflectedPoint string
	ReflectedCode  string
	Chars          []string
	Code           string
}
