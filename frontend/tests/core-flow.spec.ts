import { test, expect } from "@playwright/test"

test.describe("Core SOC flow", () => {
  test("Parser extracts IOCs → handoff Attach to case → case receives entry", async ({ page }) => {
    await page.goto("/parser")
    await page.waitForLoadState("networkidle")

    const textarea = page.locator("textarea").first()
    await expect(textarea).toBeVisible({ timeout: 15000 })

    const sampleText = `Suspicious connection from 203.0.113.44 to example-malware.com
Hash: d41d8cd98f00b204e9800998ecf8427e
Email: phish@evil.com`

    await textarea.fill(sampleText)
    await page.waitForTimeout(2000)

    // Switch to IPv4 tab
    const ipv4Tab = page.locator("button").filter({ hasText: /ipv4/i }).first()
    await expect(ipv4Tab).toBeVisible()
    await ipv4Tab.click()
    await page.waitForTimeout(200)

    // Find and click the IOC chip
    const ipChip = page.locator("button").filter({ hasText: "203[.]0[.]113[.]44" }).first()
    await ipChip.click()
    await page.waitForTimeout(300)

    // Click "Attach to case"
    const attachBtn = page.locator("button").filter({ hasText: "Attach to case" }).first()
    await expect(attachBtn).toBeVisible()
    await attachBtn.click()

    // Navigate to Cases page
    await page.goto("/case")
    await page.waitForLoadState("networkidle")
    await page.waitForTimeout(1000)

    // When no case exists yet, the parser handoff parks the entry in the
    // intake inbox; the cases page materializes a default case and applies it.
    // Open the timeline tab to read the applied entry.
    const timelineTab = page.locator("button").filter({ hasText: /^Timeline/i }).first()
    await expect(timelineTab).toBeVisible()
    await timelineTab.click()
    await page.waitForTimeout(300)

    // Verify the case shows the IOC entry with its handoff provenance badge
    await expect(page.getByText("203[.]0[.]113[.]44")).toBeVisible()
    await expect(page.getByText("handoff:/parser")).toBeVisible()
  })

  test("Parser extracts multiple IOC types", async ({ page }) => {
    await page.goto("/parser")
    await page.waitForLoadState("networkidle")

    const textarea = page.locator("textarea").first()
    await expect(textarea).toBeVisible({ timeout: 15000 })

    const sampleText = `C2 beacon from 10.0.0.5 to evil-c2.xyz:4443
MD5: d41d8cd98f00b204e9800998ecf8427e
Phish from scammer@phish.net with malicious attachment`

    await textarea.fill(sampleText)
    await page.waitForTimeout(2000)

    // All tab should show counts
    const allTab = page.locator("button").filter({ hasText: "all ·" })
    await expect(allTab).toBeVisible()

    // Individual type tabs should be present
    const domainTab = page.locator("button").filter({ hasText: /domain · /i })
    await expect(domainTab).toBeVisible()
    const ipv4Tab = page.locator("button").filter({ hasText: /ipv4 · /i })
    await expect(ipv4Tab).toBeVisible()
    const emailTab = page.locator("button").filter({ hasText: /email · /i })
    await expect(emailTab).toBeVisible()
  })

  test("SIEM event pivots into a case notebook entry", async ({ page }) => {
    await page.goto("/siem")
    await page.waitForLoadState("networkidle")

    const textarea = page.locator("textarea").first()
    await expect(textarea).toBeVisible({ timeout: 15000 })

    await textarea.fill(`{"ts":"2025-01-15T10:15:01Z","src_ip":"45.33.32.156","user":"svc_db","message":"Failed password for svc_db from 45.33.32.156 port 22 ssh2"}
{"ts":"2025-01-15T10:15:09Z","src_ip":"45.33.32.156","user":"svc_db","message":"Failed password for svc_db from 45.33.32.156 port 22 ssh2"}`)
    await page.locator("button").filter({ hasText: /^ingest/i }).first().click()
    await page.waitForTimeout(2500)

    // Expand the first event row and pivot
    await page.locator("table tbody tr").first().click()
    await page.waitForTimeout(300)
    const pivotBtn = page.locator("button").filter({ hasText: "pivot to case" }).first()
    await expect(pivotBtn).toBeVisible()
    await pivotBtn.click()
    await page.waitForTimeout(1000)

    // Case page materializes a default case and applies the parked entry
    const timelineTab = page.locator("button").filter({ hasText: /^Timeline/i }).first()
    await expect(timelineTab).toBeVisible({ timeout: 15000 })
    await timelineTab.click()
    await page.waitForTimeout(300)

    await expect(page.getByText("handoff:/siem")).toBeVisible()
    await expect(page.getByText("Failed password for svc_db")).toBeVisible()
    await expect(page.getByText("45.33.32.156 →")).toBeVisible()
  })

  test("SIEM saved hunts persist and restore the view", async ({ page }) => {
    await page.goto("/siem")
    await page.waitForLoadState("networkidle")

    const textarea = page.locator("textarea").first()
    await expect(textarea).toBeVisible({ timeout: 15000 })

    await textarea.fill(`{"ts":"2025-01-15T10:15:01Z","src_ip":"45.33.32.156","user":"svc_db","message":"Failed password for svc_db from 45.33.32.156 port 22 ssh2"}`)
    await page.locator("button").filter({ hasText: /^ingest/i }).first().click()
    await page.waitForTimeout(2000)

    // Save the current view as a hunt
    await page.locator("button").filter({ hasText: "save view" }).click()
    await page.locator("input[placeholder='hunt name']").fill("ssh probe")
    await page.locator("button").filter({ hasText: /^save$/ }).click()
    await expect(page.locator("button").filter({ hasText: "ssh probe" })).toBeVisible()

    // Reload — the hunt chip must survive
    await page.goto("/siem")
    await page.waitForLoadState("networkidle")
    const huntChip = page.locator("button").filter({ hasText: "ssh probe" })
    await expect(huntChip).toBeVisible({ timeout: 15000 })

    // Loading the hunt re-ingests the saved events into a fresh session
    await huntChip.click()
    await page.waitForTimeout(2500)
    await expect(page.getByText("· 1 rows")).toBeVisible()
    await expect(page.getByRole("table").getByRole("button", { name: /Failed password for svc_db/ })).toBeVisible()
  })
})
