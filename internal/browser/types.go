package browser

import "time"

// BrowserSession represents a single browser session
type BrowserSession struct {
	ID        string
	CreatedAt time.Time
	Active    bool
}

// BrowserConfig configuration for browser manager
type BrowserConfig struct {
	HeadlessMode         bool   `json:"headless-mode"`
	DisableSandbox       bool   `json:"disable-sandbox"`
	Timeout              int    `json:"timeout"`
	WaitForAlertOnlyTime int    `json:"wait-for-alert-only-time"`
	ChromiumBinaryPath   string `json:"chromium-binary-path"`
	TakeScreenshots      bool   `json:"take-screenshots"`
}

// ValidationResult contains the result of payload validation in browser
type ValidationResult struct {
	IsVulnerable       bool             `json:"is-vulnerable"`
	ExecutionDetected  bool             `json:"execution-detected"`
	ExecutionProofs    []ExecutionProof `json:"execution-proofs"`
	Error              error            `json:"error"`
	ValidationDuration time.Duration    `json:"validation-duration"`
}

// ExecutionProof contains proof of JavaScript execution
type ExecutionProof struct {
	PayloadSHA256    string    `json:"payload-sha256"`
	ExecutionType    string    `json:"execution-type"` // alert, confirm, prompt
	ExecutedAt       time.Time `json:"executed-at"`
	Evidence         string    `json:"evidence"`
	PageURL          string    `json:"page-url"`
	PageTitle        string    `json:"page-title"`
	ExecutionContext string    `json:"execution-context"`
	ScreenshotPath   string    `json:"screenshot-path"`
	ScreenshotData   []byte    `json:"screenshot-data"`
}
