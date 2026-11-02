import { defineConfig, devices } from "@playwright/test"
import { existsSync } from "node:fs"

const systemChromium = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || (existsSync("/usr/bin/chromium") ? "/usr/bin/chromium" : undefined)
const chromiumLaunchOptions = {
  args: ["--no-sandbox", "--font-render-hinting=none", "--disable-lcd-text", "--disable-dev-shm-usage", "--force-color-profile=srgb"],
  ...(systemChromium ? { executablePath: systemChromium } : {}),
}

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  workers: 4,
  expect: {
    timeout: 7_500,
  },
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["github"], ["list"]] : "list",
  use: {
    baseURL: "http://127.0.0.1:5173",
    screenshot: "only-on-failure",
    trace: "on-first-retry",
    video: "retain-on-failure",
  },
  webServer: {
    command: "npm run build && npm run preview -- --host 127.0.0.1 --port 5173 --strictPort",
    url: "http://127.0.0.1:5173",
    reuseExistingServer: false,
    timeout: 180_000,
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], launchOptions: chromiumLaunchOptions },
    },
  ],
})
