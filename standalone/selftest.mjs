// Headless test for the standalone reference viewer (index.html).
//
// Loads the page in Chromium with ALL network access mocked — Arweave
// and drand answer from the pinned fixture — then asserts:
//   1. every Phase 1–3 self-test row passes, and
//   2. Phase 4 recovers a private qub with its key, a public qub with
//      none, and a bare tx_id, and refuses a private qub without its key.
//
// Run from the repository root:
//   npm install --no-save playwright@1 && npx playwright install chromium
//   node standalone/selftest.mjs
// (In the private monorepo the page lives at public-mirror/standalone/;
// the script resolves every path relative to itself.)
//
// CHROME_BIN overrides the browser binary.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright");

const here = dirname(fileURLToPath(import.meta.url));
// Mirrored layout: standalone/ and crates/ are siblings at the repo root.
// Private layout: public-mirror/standalone/ is two levels below it.
const fixturePath = [
  join(here, "../crates/qub-core/tests/vectors/standalone_pipeline_v1.json"),
  join(here, "../../crates/qub-core/tests/vectors/standalone_pipeline_v1.json"),
].find((p) => {
  try {
    readFileSync(p);
    return true;
  } catch {
    return false;
  }
});
if (!fixturePath) throw new Error("standalone_pipeline_v1.json not found");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));

const TX = { wrapped: "A".repeat(43), bare: "B".repeat(43) };
const b64url = (hex) => Buffer.from(hex, "hex").toString("base64url");

const browser = await chromium.launch(
  process.env.CHROME_BIN ? { executablePath: process.env.CHROME_BIN } : {},
);
const failures = [];
try {
  const page = await browser.newPage();
  page.on("pageerror", (e) => failures.push("page error: " + e.message));
  await page.route("**/*", async (route) => {
    const u = new URL(route.request().url());
    if (u.host === "standalone.test") {
      const file = u.pathname === "/" ? "/index.html" : u.pathname;
      return route.fulfill({
        body: readFileSync(join(here, file)),
        contentType: file.endsWith(".js") ? "text/javascript" : "text/html",
      });
    }
    const raw = u.pathname.match(/\/raw\/([A-Za-z0-9_-]{43})$/);
    if (raw) {
      const c = fixture.cases.find((c) => TX[c.delivery] === raw[1]);
      return c
        ? route.fulfill({ body: Buffer.from(c.stored_hex, "hex") })
        : route.fulfill({ status: 404, body: "" });
    }
    const beacon = u.pathname.match(/\/public\/(\d+)$/);
    if (beacon) {
      const c = fixture.cases.find((c) => String(c.round) === beacon[1]);
      return c
        ? route.fulfill({
            contentType: "application/json",
            body: JSON.stringify({
              round: c.round,
              signature: c.signature_hex,
              randomness: c.randomness_hex,
            }),
          })
        : route.fulfill({ status: 404, body: "" });
    }
    return route.fulfill({ status: 404, body: "" });
  });

  await page.goto("https://standalone.test/");
  await page.waitForFunction(() => document.documentElement.dataset.selfTest, null, {
    timeout: 60_000,
  });
  const rows = await page.evaluate(() =>
    [...document.querySelectorAll("tbody tr")].map((tr) => tr.innerText.replace(/\s+/g, " ")),
  );
  for (const r of rows) console.log("  " + r);
  const ds = await page.evaluate(() => ({ ...document.documentElement.dataset }));
  if (ds.selfTest !== "pass") {
    failures.push(`self-tests: ${ds.selfTestPassed} / ${ds.selfTestTotal} passed`);
  }

  const priv = fixture.cases.find((c) => c.delivery === "wrapped");
  const pub = fixture.cases.find((c) => c.delivery === "bare");
  const recover = (url) =>
    page.evaluate(async (url) => {
      try {
        await window.qubStandalone.recoverFromUrl(url);
      } catch (e) {
        return { error: e.message };
      }
      return { body: document.getElementById("recover-body").textContent };
    }, url);

  const expectBody = async (label, url, c) => {
    const r = await recover(url);
    const ok = r.body === c.envelope_body_utf8;
    console.log(`  ${ok ? "ok  " : "FAIL"} recover: ${label}`);
    if (!ok) failures.push(`recover ${label}: ${JSON.stringify(r)}`);
  };
  await expectBody(
    "private link with key",
    `https://qub.social/c/${TX.wrapped}#${b64url(priv.key_hex)}`,
    priv,
  );
  await expectBody("public link without key", `https://qub.social/c/${TX.bare}`, pub);
  await expectBody("bare public tx_id", TX.bare, pub);
  const refused = await recover(`https://qub.social/c/${TX.wrapped}`);
  console.log(`  ${refused.error ? "ok  " : "FAIL"} refuse: private link without key`);
  if (!refused.error) failures.push("private link without key was not refused");
} finally {
  await browser.close();
}

if (failures.length) {
  for (const f of failures) console.error("error: " + f);
  process.exit(1);
}
console.log("standalone viewer: all checks passed");
