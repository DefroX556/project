package browser

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"image"
	"image/jpeg"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// Manager handles headless browser sessions using Chrome DevTools Protocol.
// This provides a reliable headless Chromium validation path. The implementation
// strictly follows the snapshot rules: screenshots are taken only when execution
// is confirmed (alert/confirm/prompt or verified stored execution). PNG is
// converted to JPEG and stored under snapshots/jpg/ with quality >=90.
type Manager struct {
	sessions      map[string]*BrowserSession
	sessionsMutex sync.RWMutex
	config        BrowserConfig
	isInitialized bool
	initMutex     sync.Mutex
}

// NewManager creates a new browser session manager
func NewManager(cfg BrowserConfig) *Manager {
	return &Manager{
		sessions:      make(map[string]*BrowserSession),
		config:        cfg,
		isInitialized: false,
	}
}

// Initialize prepares environment for headless browser usage. Failure to initialize
// returns an error but callers must treat browser use as optional and continue scanning.
func (m *Manager) Initialize() error {
	m.initMutex.Lock()
	defer m.initMutex.Unlock()

	if m.isInitialized {
		return nil
	}

	// Ensure snapshot directories exist
	_ = os.MkdirAll("snapshots/jpg", 0755)
	_ = os.MkdirAll("snapshots/svg", 0755)

	// chromedp uses the system Chrome/Chromium binary. If ChromiumBinaryPath is provided,
	// chromedp will use it via ExecPath option at runtime when creating contexts.
	m.isInitialized = true
	return nil
}

// helper: create chromedp context with options based on config
func (m *Manager) newContext(parent context.Context) (context.Context, context.CancelFunc) {
	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-client-side-phishing-detection", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("enable-automation", true),
	}

	if m.config.HeadlessMode {
		opts = append(opts, chromedp.Headless)
	}
	if m.config.DisableSandbox {
		opts = append(opts, chromedp.Flag("no-sandbox", true))
	}
	if m.config.ChromiumBinaryPath != "" {
		opts = append(opts, chromedp.ExecPath(m.config.ChromiumBinaryPath))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(parent, opts...)
	ctx, cancelCtx := chromedp.NewContext(allocCtx)

	return ctx, func() {
		cancelCtx()
		cancelAlloc()
	}
}

// ValidatePayload navigates to the provided URL which should already include the payload
// (scanner is responsible for injecting payload into parameters). This function waits
// for JavaScript dialogs (alert/confirm/prompt) and for a limited time specified in
// BrowserConfig.WaitForAlertOnlyTime. If execution is detected, a JPG screenshot is
// taken (quality >=90) and saved to snapshots/jpg/ with filename including target+payload hashes.
func (m *Manager) ValidatePayload(sessionID string, url string, payload string, contextStr string) *ValidationResult {
	if !m.IsInitialized() {
		return &ValidationResult{
			IsVulnerable:      false,
			ExecutionDetected: false,
			Error:             fmt.Errorf("browser not initialized"),
		}
	}

	start := time.Now()

	parent := context.Background()
	ctx, cancel := m.newContext(parent)
	defer cancel()

	// channel to receive dialog events
	dialogCh := make(chan *page.EventJavascriptDialogOpening, 1)

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *page.EventJavascriptDialogOpening:
			select {
			case dialogCh <- e:
			default:
			}
		}
	})

	// navigate
	navCtx, navCancel := context.WithTimeout(ctx, time.Duration(m.config.Timeout)*time.Second)
	defer navCancel()
	var navErr error
	navErr = chromedp.Run(navCtx, chromedp.Navigate(url))
	if navErr != nil {
		return &ValidationResult{IsVulnerable: false, ExecutionDetected: false, Error: navErr, ValidationDuration: time.Since(start)}
	}

	// wait for dialog up to configured WaitForAlertOnlyTime seconds
	waitSec := m.config.WaitForAlertOnlyTime
	if waitSec <= 0 {
		waitSec = 5
	}

	select {
	case dlg := <-dialogCh:
		// Execution confirmed - TAKE SCREENSHOT
		proof := ExecutionProof{
			PayloadSHA256:    fmt.Sprintf("%x", sha256.Sum256([]byte(payload))),
			ExecutionType:    dialogTypeFromString(dlg.Type.String()),
			ExecutedAt:       time.Now(),
			Evidence:         dlg.Message,
			PageURL:          url,
			PageTitle:        "",
			ExecutionContext: contextStr,
		}

		// take screenshot (full page); chromedp returns PNG bytes
		var pngBuf []byte
		if err := chromedp.Run(ctx, chromedp.FullScreenshot(&pngBuf, 90)); err == nil {
			// convert PNG to JPEG and save
			jpgBytes, err := convertPNGtoJPG(pngBuf, 95)
			if err == nil {
				// filename: targethash_payloadhash_timestamp.jpg
				targetHash := fmt.Sprintf("%x", sha256.Sum256([]byte(url)))
				payloadHash := fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))
				fname := fmt.Sprintf("%s_%s_%d.jpg", targetHash[:12], payloadHash[:12], time.Now().Unix())
				outPath := filepath.Join("snapshots", "jpg", fname)
				if err := ioutil.WriteFile(outPath, jpgBytes, 0644); err == nil {
					proof.ScreenshotPath = outPath
					proof.ScreenshotData = []byte(base64.StdEncoding.EncodeToString(jpgBytes))
				}
			}
		}

		// fill title if possible
		var title string
		_ = chromedp.Run(ctx, chromedp.Title(&title))
		proof.PageTitle = title

		return &ValidationResult{
			IsVulnerable:       true,
			ExecutionDetected:  true,
			ExecutionProofs:    []ExecutionProof{proof},
			ValidationDuration: time.Since(start),
		}
	case <-time.After(time.Duration(waitSec) * time.Second):
		// No execution detected
		return &ValidationResult{IsVulnerable: false, ExecutionDetected: false, ValidationDuration: time.Since(start)}
	}
}

// VerifyStoredXSS revisits the URL to check for stored payload execution. It opens a fresh
// browser context and waits for dialogs similarly to ValidatePayload.
func (m *Manager) VerifyStoredXSS(url string, sessionID string) *ValidationResult {
	// For stored XSS, behavior is similar: navigate and wait for dialogs
	return m.ValidatePayload(sessionID, url, "[stored-check]", "stored")
}

// convertPNGtoJPG converts a PNG image bytes to JPEG bytes with given quality (0-100).
func convertPNGtoJPG(pngBytes []byte, quality int) ([]byte, error) {
	img, _, err := image.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	opts := &jpeg.Options{Quality: quality}
	if err := jpeg.Encode(&buf, img, opts); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// dialogTypeFromString maps CDP dialog type strings to ExecutionType values
func dialogTypeFromString(s string) string {
	switch s {
	case "alert":
		return "alert"
	case "confirm":
		return "confirm"
	case "prompt":
		return "prompt"
	default:
		return "dialog"
	}
}

// CaptureScreenshot converts the current page to JPEG and returns bytes. Only used after execution confirmation.
func (m *Manager) CaptureScreenshot(sessionID string) ([]byte, error) {
	if !m.IsInitialized() {
		return nil, fmt.Errorf("browser not initialized")
	}
	parent := context.Background()
	ctx, cancel := m.newContext(parent)
	defer cancel()

	var pngBuf []byte
	if err := chromedp.Run(ctx, chromedp.FullScreenshot(&pngBuf, 90)); err != nil {
		return nil, err
	}
	jpg, err := convertPNGtoJPG(pngBuf, 95)
	if err != nil {
		return nil, err
	}
	return jpg, nil
}

// Shutdown gracefully closes any resources (no-op for chromedp contexts created per call)
func (m *Manager) Shutdown() error {
	m.initMutex.Lock()
	defer m.initMutex.Unlock()
	m.isInitialized = false
	return nil
}

// IsInitialized returns whether browser manager is ready
func (m *Manager) IsInitialized() bool {
	m.initMutex.Lock()
	defer m.initMutex.Unlock()
	return m.isInitialized
}
