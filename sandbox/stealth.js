// Playwright stealth init script — hides automation signals from bot detection.
// Ported from shannon (apps/worker/src/ai/playwright-config-writer.ts).
// Usage: playwright-cli --init-script stealth.js

delete Object.getPrototypeOf(navigator).webdriver;
Object.defineProperty(navigator, "plugins", {
  get: () => {
    const arr = [
      { name: "Chrome PDF Plugin", filename: "internal-pdf-viewer", description: "Portable Document Format" },
      { name: "Chrome PDF Viewer", filename: "mhjfbmdgcfjbbpaeojofohoefgiehjai", description: "" },
      { name: "Native Client", filename: "internal-nacl-plugin", description: "" },
    ];
    arr.__proto__ = PluginArray.prototype;
    return arr;
  },
});
window.chrome = window.chrome || {};
window.chrome.runtime = window.chrome.runtime || {
  PlatformOs: { MAC: "mac", WIN: "win", ANDROID: "android", CROS: "cros", LINUX: "linux", OPENBSD: "openbsd" },
  PlatformArch: { ARM: "arm", X86_32: "x86-32", X86_64: "x86-64" },
  PlatformNaclArch: { ARM: "arm", X86_32: "x86-32", X86_64: "x86-64" },
  RequestUpdateCheckStatus: { THROTTLED: "throttled", NO_UPDATE: "no_update", UPDATE_AVAILABLE: "update_available" },
  OnInstalledReason: { INSTALL: "install", UPDATE: "update", CHROME_UPDATE: "chrome_update", SHARED_MODULE_UPDATE: "shared_module_update" },
  OnRestartRequiredReason: { APP_UPDATE: "app_update", OS_UPDATE: "os_update", PERIODIC: "periodic" },
};
