const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function verifyXSS(url, payload, sessionId, timeout = 30, waitTime = 5) {
  let browser;
  try {
    // Launch browser in strict headless mode
    browser = await puppeteer.launch({
      headless: 'new', // strict headless
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--single-process',
        '--disable-gpu'
      ]
    });

    const page = await browser.newPage();

    // Set viewport
    await page.setViewport({ width: 1280, height: 720 });

    let dialogDetected = false;
    let dialogInfo = null;

    // Listen for dialog events
    page.on('dialog', async (dialog) => {
      dialogDetected = true;
      dialogInfo = {
        type: dialog.type(),
        message: dialog.message()
      };

      // Dismiss the dialog to continue
      await dialog.dismiss();
    });

    // Navigate to URL
    await page.goto(url, {
      waitUntil: 'networkidle2',
      timeout: timeout * 1000
    });

    // Wait for dialog or timeout
    const startTime = Date.now();
    while (!dialogDetected && (Date.now() - startTime) < (waitTime * 1000)) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    if (dialogDetected && dialogInfo) {
      // Take screenshot as JPG
      const screenshotBuffer = await page.screenshot({
        type: 'jpeg',
        quality: 95,
        fullPage: true
      });

      // Generate filename
      const targetHash = crypto.createHash('sha256').update(url).digest('hex').substring(0, 12);
      const payloadHash = crypto.createHash('sha256').update(payload || 'headless-check').digest('hex').substring(0, 12);
      const timestamp = Math.floor(Date.now() / 1000);
      const filename = `${targetHash}_${payloadHash}_${timestamp}.jpg`;

      // Ensure directory exists
      const jpgDir = path.join(__dirname, 'snapshots', 'jpg');
      if (!fs.existsSync(jpgDir)) {
        fs.mkdirSync(jpgDir, { recursive: true });
      }

      const filepath = path.join(jpgDir, filename);
      fs.writeFileSync(filepath, screenshotBuffer);

      // Get page title
      const title = await page.title();

      return {
        isVulnerable: true,
        executionDetected: true,
        executionProofs: [{
          payloadSHA256: crypto.createHash('sha256').update(payload || 'headless-check').digest('hex'),
          executionType: dialogInfo.type,
          executedAt: new Date().toISOString(),
          evidence: dialogInfo.message,
          pageURL: url,
          pageTitle: title,
          screenshotPath: filepath,
          screenshotData: screenshotBuffer.toString('base64'),
          executionContext: 'headless'
        }],
        validationDuration: Date.now() - startTime
      };
    } else {
      return {
        isVulnerable: false,
        executionDetected: false,
        validationDuration: Date.now() - startTime
      };
    }

  } catch (error) {
    console.error('Puppeteer verification error:', error);
    return {
      isVulnerable: false,
      executionDetected: false,
      error: error.message,
      validationDuration: 0
    };
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

// Main execution
if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.error('Usage: node puppeteer_verifier.js <url> [payload] [sessionId] [timeout] [waitTime]');
    process.exit(1);
  }

  const url = args[0];
  const payload = args[1] || 'headless-check';
  const sessionId = args[2] || 'session_' + Date.now();
  const timeout = parseInt(args[3]) || 30;
  const waitTime = parseInt(args[4]) || 5;

  verifyXSS(url, payload, sessionId, timeout, waitTime)
    .then(result => {
      console.log(JSON.stringify(result, null, 2));
    })
    .catch(error => {
      console.error('Error:', error);
      process.exit(1);
    });
}

module.exports = { verifyXSS };
