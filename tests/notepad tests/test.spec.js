const { test, expect } = require('@playwright/test');

test('BusCMMS Test', async ({ page }) => {

  await page.goto('https://buscmms.com/');

  await page.waitForTimeout(3000);

});