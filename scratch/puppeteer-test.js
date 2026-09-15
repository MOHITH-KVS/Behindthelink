const puppeteer = require('puppeteer');
const path = require('path');

async function runTest() {
  const extensionPath = path.resolve(__dirname);
  const browser = await puppeteer.launch({
    headless: false,
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`
    ]
  });

  // Get the background page (service worker)
  const targets = await browser.targets();
  const backgroundTarget = targets.find(t => t.type() === 'service_worker');
  const sw = await backgroundTarget.worker();

  // Listen for console messages from the service worker
  sw.on('console', msg => console.log('SW_LOG:', msg.text()));

  // Open test-lab.html
  const page = await browser.newPage();
  const testLabUrl = `file:///${path.resolve(__dirname, 'test', 'test-lab.html').replace(/\\/g, '/')}`;
  await page.goto(testLabUrl);

  // Find the link
  const linkSelector = 'a[href="https://example.com/test-observation"]';
  await page.waitForSelector(linkSelector);

  console.log('Hovering link...');
  await page.hover(linkSelector);
  
  await new Promise(resolve => setTimeout(resolve, 2000)); // wait for hover resolution

  console.log('Clicking link...');
  // Click the link, which will navigate the page
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle0' }),
    page.click(linkSelector)
  ]);

  console.log('Navigated to:', page.url());
  
  // Wait a bit
  await new Promise(resolve => setTimeout(resolve, 2000));

  console.log('Returning to test lab (clicking Back)...');
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle0' }),
    page.goBack()
  ]);

  console.log('Returned to:', page.url());

  // Wait a bit
  await new Promise(resolve => setTimeout(resolve, 2000));

  console.log('Turning Wi-Fi OFF (Offline mode)...');
  await page.setOfflineMode(true);

  console.log('Hovering link again...');
  await page.hover(linkSelector);

  await new Promise(resolve => setTimeout(resolve, 5000)); // wait for hover resolution

  // Extract the popup text
  try {
    // The popup might be in the Shadow DOM or just in the page body.
    // In BehindTheLink, it creates a custom element <btl-preview-card>
    const popupText = await page.evaluate(() => {
      const card = document.querySelector('btl-preview-card');
      return card ? card.shadowRoot.textContent : 'No card found';
    });
    console.log('Popup Text:', popupText);
  } catch (e) {
    console.log('Error reading popup:', e);
  }

  await browser.close();
}

runTest().catch(console.error);
