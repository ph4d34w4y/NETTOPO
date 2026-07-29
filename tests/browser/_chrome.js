/* Locates a Chromium/Chrome executable for Puppeteer.
 * Priority: $CHROME_PATH env var -> puppeteer's bundled browser -> common system paths.
 * Set CHROME_PATH explicitly if none is found:  CHROME_PATH=/path/to/chrome npm run test:browser
 */
const fs = require('fs');
function find() {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  try { return require('puppeteer').executablePath(); } catch (e) {}
  const candidates = [
    '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium',
    '/usr/bin/chromium-browser', '/snap/bin/chromium',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  ];
  for (const c of candidates) { try { if (fs.existsSync(c)) return c; } catch (e) {} }
  throw new Error('No Chrome/Chromium found. Set the CHROME_PATH environment variable to your browser executable.');
}
module.exports = { find };
