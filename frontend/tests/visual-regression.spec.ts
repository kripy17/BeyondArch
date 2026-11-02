import { test, expect } from "@playwright/test"

const ROUTES = [
  { path: "/", name: "dashboard" },
  { path: "/activity", name: "activity" },
  { path: "/attachment", name: "attachment" },
  { path: "/case", name: "cases" },
  { path: "/chef", name: "chef" },
  { path: "/detection", name: "detection" },
  { path: "/developer", name: "developer" },
  { path: "/developer/components", name: "developer-components" },
  { path: "/diff", name: "diff" },
  { path: "/file", name: "file" },
  { path: "/guide", name: "guide" },
  { path: "/intake", name: "intake" },
  { path: "/intel", name: "intel" },
  { path: "/investigation", name: "investigation" },
  { path: "/logs", name: "logs" },
  { path: "/mitre", name: "mitre" },
  { path: "/operations", name: "operations" },
  { path: "/parser", name: "parser" },
  { path: "/pcap", name: "pcap" },
  { path: "/phishing", name: "phishing" },
  { path: "/report/demo-case", name: "report" },
  { path: "/settings", name: "settings" },
  { path: "/siem", name: "siem" },
  { path: "/sigma-tester", name: "sigma-tester" },
  { path: "/snippets", name: "snippets" },
  { path: "/threat-actors", name: "threat-actors" },
  { path: "/timeline", name: "timeline" },
  { path: "/triage", name: "triage" },
  { path: "/url", name: "url" },
  { path: "/validation", name: "validation" },
  { path: "/regex-playground", name: "regex-playground" },
]

test.beforeEach(async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" })
  await page.addStyleTag({
    content:
      "*,*::before,*::after{transition:none!important;animation:none!important;scroll-behavior:auto!important}",
  })
})

const settleAndFreeze = async (page: import("@playwright/test").Page) => {
  await page.waitForLoadState("networkidle")
  await page.evaluate(async () => {
    await Promise.allSettled([...document.fonts].map((f) => f.load()))
    await document.fonts.ready
  })
  await page.waitForTimeout(400)
  await page.clock.install({ time: new Date("2026-08-13T12:00:00.000Z") })
}

test.describe("Visual regression: layout invariants + pixel baselines", () => {
  for (const { path, name } of ROUTES) {
    test(`route ${name} renders without page errors or horizontal overflow and matches baseline`, async ({ page }) => {
      const pageErrors: string[] = []
      page.on("pageerror", (err) => pageErrors.push(String(err)))

      await page.goto(path)
      await settleAndFreeze(page)

      expect(pageErrors, `page errors on /${path}`).toEqual([])

      const hasOverflow = await page.evaluate(() => {
        const body = document.body
        return body.scrollWidth > body.clientWidth + 1
      })
      expect(hasOverflow, "body must not scroll horizontally").toBe(false)

      await expect(page).toHaveScreenshot(`${name}.png`, { caret: "hide", maxDiffPixelRatio: 0.01 })
    })
  }

  test("investigation graph renders a seeded case without overflow and matches baseline", async ({ page }) => {
    const pageErrors: string[] = []
    page.on("pageerror", (err) => pageErrors.push(String(err)))

    const seed = [
      {
        id: "GRAPH-1",
        title: "Visual Regression Seed",
        tags: ["test"],
        createdAt: "2026-08-01T00:00:00.000Z",
        state: "active",
        entries: [],
        findings: [
          { id: "f1", severity: "high", title: "Malicious PowerShell download", detail: "d", source: "test", iocs: ["203.0.113.44"], technique: "T1059.001" },
        ],
        iocs: [{ value: "203.0.113.44", type: "ipv4", context: "", source: "test", severity: "high", id: "i-1" }],
      },
    ]
    await page.addInitScript((payload) => {
      localStorage.setItem("ba.cases.v2", JSON.stringify(payload))
      localStorage.setItem("ba.cases.active", "GRAPH-1")
    }, seed)

    await page.goto("/case")
    await settleAndFreeze(page)

    await expect(page.getByRole("heading", { name: "Visual Regression Seed" })).toBeVisible({ timeout: 15000 })
    expect(pageErrors).toEqual([])

    const hasOverflow = await page.evaluate(() => document.body.scrollWidth > document.body.clientWidth + 1)
    expect(hasOverflow).toBe(false)

    await expect(page).toHaveScreenshot("investigation-graph.png", { caret: "hide", maxDiffPixelRatio: 0.01 })
  })
})