#!/usr/bin/env node

/**
 * CORE REQUIREMENT: XSS Execution Proof System
 * 
 * This script reads DalFox JSON results and proves real XSS execution
 * using a headless Chromium browser with Puppeteer.
 * 
 * Usage: node xss-prover.js dalfox-results.json
 */

const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class XSSProver {
    constructor() {
        this.browser = null;
        this.screenshotsDir = 'snapshots/jpg';
        this.ensureScreenshotsDir();
    }

    ensureScreenshotsDir() {
        if (!fs.existsSync(this.screenshotsDir)) {
            fs.mkdirSync(this.screenshotsDir, { recursive: true });
        }
    }

    /**
     * Calculate SHA256 hash of a string
     */
    hashString(str) {
        return crypto.createHash('sha256').update(str).digest('hex').substring(0, 12);
    }

    /**
     * Read and parse DalFox JSON results
     */
    async loadDalFoxResults(jsonFilePath) {
        if (!fs.existsSync(jsonFilePath)) {
            throw new Error(`DalFox results file not found: ${jsonFilePath}`);
        }

        const content = fs.readFileSync(jsonFilePath, 'utf8');
        const results = JSON.parse(content);

        // Filter only vulnerable results (not reflected)
        return results.filter(result => {
            return result.type === 'V' || (result.message_str && result.message_str.includes('DOM Object'));
        });
    }

    /**
     * Test a single URL for XSS execution
     */
    async testXSSExecution(url, payload, evidence) {
        console.log(`[TESTING] ${url}`);

        const page = await this.browser.newPage();
        
        try {
            // Track if any dialog appears
            let dialogDetected = false;
            let dialogMessage = '';
            let dialogType = '';

            // Listen for JavaScript dialogs (alert, confirm, prompt)
            page.on('dialog', async dialog => {
                dialogDetected = true;
                dialogType = dialog.type();
                dialogMessage = dialog.message();
                
                console.log(`[EXECUTION DETECTED] ${dialogType} popup: "${dialogMessage}"`);
                
                // Accept the dialog to continue
                await dialog.accept();
            });

            // Navigate to the URL
            await page.goto(url, { 
                waitUntil: 'networkidle2',
                timeout: 30000 
            });

            // Wait a bit for any delayed JavaScript execution
            await page.waitForTimeout(3000);

            // Check if dialog was detected
            if (dialogDetected) {
                // CORE REQUIREMENT: Take screenshot ONLY after execution is confirmed
                await this.takeScreenshot(page, url, payload);
                
                return {
                    url,
                    payload,
                    evidence,
                    executionDetected: true,
                    dialogType,
                    dialogMessage,
                    screenshotTaken: true
                };
            } else {
                console.log(`[NO EXECUTION] No popup detected for ${url}`);
                return {
                    url,
                    payload,
                    evidence,
                    executionDetected: false,
                    screenshotTaken: false
                };
            }

        } catch (error) {
            console.log(`[ERROR] Failed to test ${url}: ${error.message}`);
            return {
                url,
                payload,
                evidence,
                executionDetected: false,
                error: error.message,
                screenshotTaken: false
            };
        } finally {
            await page.close();
        }
    }

    /**
     * Take screenshot with proper naming convention
     */
    async takeScreenshot(page, url, payload) {
        const urlHash = this.hashString(url);
        const payloadHash = this.hashString(payload);
        const timestamp = Date.now();
        
        const filename = `${urlHash}_${payloadHash}_${timestamp}.jpg`;
        const filepath = path.join(this.screenshotsDir, filename);

        // Take screenshot as JPG with quality >=90%
        const screenshot = await page.screenshot({
            type: 'jpeg',
            quality: 95,
            fullPage: true
        });
        
        // Save the JPG screenshot
        fs.writeFileSync(filepath, screenshot);
        
        console.log(`[SCREENSHOT SAVED] ${filepath}`);
        return filepath;
    }


    /**
     * Main execution function
     */
    async proveExecutions(dalfoxJsonFile) {
        console.log('[XSS PROVER] Starting XSS execution proof system...');
        console.log(`[INPUT] Reading DalFox results from: ${dalfoxJsonFile}`);

        // Load DalFox results
        const vulnerableUrls = await this.loadDalFoxResults(dalfoxJsonFile);
        console.log(`[FOUND] ${vulnerableUrls.length} vulnerable URLs to test`);

        // Launch browser
        this.browser = await puppeteer.launch({
            headless: true,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage'
            ]
        });

        console.log('[BROWSER] Headless Chromium launched');

        // Test each vulnerable URL
        const proofResults = [];
        
        for (const result of vulnerableUrls) {
            const proof = await this.testXSSExecution(
                result.data, 
                result.payload || result.evidence, 
                result.evidence
            );
            proofResults.push(proof);
            
            // Small delay between tests
            await new Promise(resolve => setTimeout(resolve, 1000));
        }

        // Close browser
        await this.browser.close();
        console.log('[BROWSER] Headless Chromium closed');

        // Generate proof report
        const validExecutions = proofResults.filter(r => r.executionDetected);
        const invalidExecutions = proofResults.filter(r => !r.executionDetected);

        console.log('\n=== XSS EXECUTION PROOF REPORT ===');
        console.log(`Total URLs tested: ${proofResults.length}`);
        console.log(`Valid executions (screenshot taken): ${validExecutions.length}`);
        console.log(`Invalid executions (no proof): ${invalidExecutions.length}`);
        
        if (validExecutions.length > 0) {
            console.log('\n[VALID EXECUTIONS] Screenshots saved:');
            validExecutions.forEach(exec => {
                console.log(`  ✅ ${exec.url} (${exec.dialogType})`);
            });
        }

        if (invalidExecutions.length > 0) {
            console.log('\n[INVALID EXECUTIONS] No proof found:');
            invalidExecutions.forEach(exec => {
                console.log(`  ❌ ${exec.url}`);
            });
        }

        // Save proof results
        const proofReportPath = 'xss-proof-report.json';
        fs.writeFileSync(proofReportPath, JSON.stringify({
            timestamp: new Date().toISOString(),
            totalTested: proofResults.length,
            validExecutions: validExecutions.length,
            invalidExecutions: invalidExecutions.length,
            results: proofResults
        }, null, 2));

        console.log(`\n[REPORT] Proof report saved to: ${proofReportPath}`);
        console.log(`[SCREENSHOTS] Location: ${this.screenshotsDir}/`);
        
        return proofResults;
    }
}

// Main execution
async function main() {
    const args = process.argv.slice(2);
    
    if (args.length === 0) {
        console.log('Usage: node xss-prover.js <dalfox-results.json>');
        console.log('\nExample:');
        console.log('  1. Run DalFox: ./dalfox url "https://target.com/?q=test" --format json -o results.json');
        console.log('  2. Run proof: node xss-prover.js results.json');
        process.exit(1);
    }

    const dalfoxJsonFile = args[0];
    
    try {
        const prover = new XSSProver();
        await prover.proveExecutions(dalfoxJsonFile);
    } catch (error) {
        console.error('[FATAL ERROR]', error.message);
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    main();
}

module.exports = XSSProver;
