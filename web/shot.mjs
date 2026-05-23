import puppeteer from "puppeteer-core";

const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const b = await puppeteer.launch({
  executablePath: CHROME,
  headless: "new",
  defaultViewport: { width: 1600, height: 1000, deviceScaleFactor: 2 },
  args: ["--no-sandbox", "--disable-gpu", "--hide-scrollbars"],
});
const p = await b.newPage();
await p.goto("http://localhost:8080/", { waitUntil: "domcontentloaded" });
await sleep(1200);

// Set values via the native setter + input event so React's controlled state updates.
await p.evaluate(() => {
  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
  const els = document.querySelectorAll("input.input");
  setter.call(els[0], "admin");
  els[0].dispatchEvent(new Event("input", { bubbles: true }));
  setter.call(els[1], "sentinel-admin");
  els[1].dispatchEvent(new Event("input", { bubbles: true }));
});
await sleep(300);
await p.click("button.btn-primary");
await sleep(3500);
await p.screenshot({ path: "/tmp/shot-overview.png" });
console.log("overview captured");

async function nav(text, file) {
  const links = await p.$$("a.nav-item");
  for (const l of links) {
    const t = await p.evaluate((e) => e.textContent, l);
    if (t && t.includes(text)) {
      await l.click();
      break;
    }
  }
  await sleep(1800);
  await p.screenshot({ path: file });
  console.log(file, "captured");
}

await nav("Detections", "/tmp/shot-detections.png");
await nav("Endpoints", "/tmp/shot-endpoints.png");
await nav("Data Loss", "/tmp/shot-dlp.png");
await nav("Internet", "/tmp/shot-internet.png");
await nav("Response", "/tmp/shot-responses.png");
await b.close();
console.log("done");
