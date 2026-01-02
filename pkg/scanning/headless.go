package scanning

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"time"

	"github.com/hahwul/dalfox/v2/internal/browser"
	"github.com/hahwul/dalfox/v2/pkg/model"
)

var browserMgr *browser.Manager

func init() {
	// Initialize browser manager (kept for compatibility but will be replaced by Puppeteer)
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
// Uses Puppeteer if --puppeteer-headless flag is set, otherwise uses chromedp
func CheckXSSWithHeadless(url string, options model.Options) bool {
	if options.PuppeteerHeadless {
		return checkXSSWithPuppeteer(url, options)
	}
	return checkXSSWithChromedp(url, options)
}

// checkXSSWithPuppeteer uses Puppeteer for headless verification
// Takes JPG screenshots ONLY after alert/confirm/prompt execution
func checkXSSWithPuppeteer(url string, options model.Options) bool {
	// Generate a unique session ID for this validation
	sessionID := fmt.Sprintf("session_%d", time.Now().UnixNano())

	// Call Puppeteer verification script
	cmd := exec.Command("node", "puppeteer_verifier.js",
		url,
		"[headless-check]",
		sessionID,
		strconv.Itoa(options.HeadlessTimeout),
		strconv.Itoa(options.HeadlessTimeout/6), // waitTime as fraction of timeout
	)

	output, err := cmd.Output()
	if err != nil {
		log.Printf("Puppeteer verification failed: %v", err)
		return false
	}

	// Parse JSON result
	var result struct {
		IsVulnerable      bool `json:"isVulnerable"`
		ExecutionDetected bool `json:"executionDetected"`
		ExecutionProofs   []struct {
			ScreenshotPath string `json:"screenshotPath"`
		} `json:"executionProofs"`
		Error string `json:"error,omitempty"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		log.Printf("Failed to parse Puppeteer result: %v", err)
		return false
	}

	if result.ExecutionDetected {
		// Log screenshot if available
		if len(result.ExecutionProofs) > 0 && result.ExecutionProofs[0].ScreenshotPath != "" {
			log.Printf("CORE REQUIREMENT: Screenshot saved to %s", result.ExecutionProofs[0].ScreenshotPath)
		}
		return true
	}

	return false
}

// checkXSSWithChromedp uses chromedp (original implementation) for headless verification
func checkXSSWithChromedp(url string, options model.Options) bool {
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

// GetBrowserManager returns the browser manager instance
// This allows other parts of the code to access browser validation functionality
func GetBrowserManager() *browser.Manager {
	return browserMgr
}
