import { defineConfig, devices } from '@playwright/test';

// BASE_URL points at Snare's gateway inside the lab network. Running the
// suite against Juice Shop directly (http://juice-shop:3000) is also valid,
// for example to compare latency.
export default defineConfig({
  testDir: './tests',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list'], ['json', { outputFile: process.env.RESULTS_DIR ? `${process.env.RESULTS_DIR}/report.json` : 'out/report.json' }]],
  outputDir: process.env.RESULTS_DIR ? `${process.env.RESULTS_DIR}/artifacts` : 'out/artifacts',
  use: {
    baseURL: process.env.BASE_URL ?? 'http://snare:8000',
    ...devices['Desktop Chrome'],
    screenshot: 'only-on-failure',
    trace: 'off',
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
  },
});
