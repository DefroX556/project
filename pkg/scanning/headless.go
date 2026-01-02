package scanning

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/hahwul/dalfox/v2/internal/browser"
	"github.com/hahwul/dalfox/v2/pkg/model"
)

var chromeCtx context.Context
var chromeCancel context.CancelFunc
var browserMgr *browser.Manager

func init() {
	chromeCtx, chromeCancel = chromedp.NewContext(context.Background())
	if chromeCtx == nil {
		log.Println("Failed to create chrome context")
	}

	// Initialize browser manager with CORE REQUIREMENT screenshot support
	browserMgr = browser.NewManager(browser.BrowserConfig{
		HeadlessMode:         true,
		DisableSandbox:       false,
		Timeout:              30,
		WaitForAlertOnlyTime: 5,
		ChromiumBinaryPath:   "",
		TakeScreenshots:      true,
	})
	browserMgr.Initialize()
}

// CheckXSSWithHeadless is XSS Testing with headless browser
// UPDATED: Now includes CORE REQUIREMENT browser validation with JPG/SVG screenshots
func CheckXSSWithHeadless(url string, options model.Options) bool {
	// Generate a unique session ID for this validation
	sessionID := fmt.Sprintf("session_%d", time.Now().UnixNano())

	// Use the new browser manager with screenshot capabilities
	validationResult := browserMgr.ValidatePayload(sessionID, url, "[headless-check]", "headless")

	if validationResult != nil && validationResult.ExecutionDetected {
		// CORE REQUIREMENT: Take screenshots ONLY when execution is confirmed
		if validationResult.ExecutionProofs != nil && len(validationResult.ExecutionProofs) > 0 {
			proof := validationResult.ExecutionProofs[0]
			if proof.ScreenshotPath != "" {
				log.Printf("CORE REQUIREMENT: Screenshot saved to %s", proof.ScreenshotPath)
			}
		}
		return true
	}

	return false
}

func setheaders(host string, headers map[string]interface{}) chromedp.Tasks {
	return chromedp.Tasks{
		network.Enable(),
		network.SetExtraHTTPHeaders(network.Headers(headers)),
		chromedp.Navigate(host),
	}
}

// GetBrowserManager returns the browser manager instance
// This allows other parts of the code to access browser validation functionality
func GetBrowserManager() *browser.Manager {
	return browserMgr
}
