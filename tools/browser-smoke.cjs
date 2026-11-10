/* Optional development check: npm package playwright is required. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');

(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.PLAYWRIGHT_CHANNEL ? { channel: process.env.PLAYWRIGHT_CHANNEL } : {}) });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()); });
    await page.goto('http://127.0.0.1:8766');
    await page.locator('#empty-state').waitFor({ state: 'visible' });
    await page.getByRole('button', { name: /Загрузить демо-сценарий/ }).click();
    await page.waitForFunction(() => document.querySelector('#metric-events').textContent === '98');
    assert.equal(await page.locator('#incident-rows tr').count(), 6);
    await page.getByRole('searchbox').fill('SSH-003');
    assert.equal(await page.locator('#incident-rows tr').count(), 1);
    await page.getByRole('button', { name: /Открыть Success after failures/ }).click();
    await page.locator('#detail-dialog').waitFor({ state: 'visible' });
    assert.equal(await page.locator('.detail-events tbody tr').count(), 8);
    await page.getByRole('textbox', { name: 'Комментарий аналитика' }).fill('<img src=x onerror=alert(1)> Проверено в браузере');
    await page.getByLabel('Статус инцидента').selectOption('investigating');
    await page.getByRole('button', { name: 'Сохранить решение' }).click();
    await page.locator('.history-item').waitFor();
    assert.equal(await page.locator('.history-item img').count(), 0);
    assert.match(await page.locator('.history-item').textContent(), /<img src=x/);
    assert.equal(await page.getByLabel('Статус инцидента').inputValue(), 'investigating');
    await page.locator('#detail-dialog').getByRole('button', { name: 'Закрыть', exact: true }).click();
    const report = await page.request.get('http://127.0.0.1:8766/api/export');
    assert.match(await report.text(), /investigating/);
    assert.match(await report.text(), /&lt;img/);
    await page.getByRole('searchbox').fill('');
    await page.getByRole('button', { name: 'Импорт логов', exact: false }).click();
    await page.locator('#import-format').selectOption('jsonl');
    await page.locator('#import-source').fill('browser-reject');
    await page.locator('#import-text').fill('bad-json');
    await page.getByRole('button', { name: 'Импортировать и проверить' }).click();
    await page.locator('#import-dialog').waitFor({ state: 'hidden' });
    assert.match(await page.locator('#notice').textContent(), /отклонено 1/);
    for (const name of ['Журнал событий', 'Правила детекции', 'Обзор']) {
      await page.getByRole('button', { name, exact: false }).click();
    }
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    assert.deepEqual(errors, []);
    console.log('Browser smoke: demo, search, triage, escaping, export, import, navigation, mobile — OK');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
