"""reCAPTCHA v3 solver using Playwright browser automation."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from playwright.async_api import Browser, Playwright, async_playwright

from ..core.config import Config

log = logging.getLogger(__name__)

# JS executed inside the browser to obtain a reCAPTCHA v3 token.
# Handles both standard and enterprise reCAPTCHA libraries.
_EXECUTE_JS = """
([key, action]) => new Promise((resolve, reject) => {
    const gr = window.grecaptcha?.enterprise || window.grecaptcha;
    if (gr && typeof gr.execute === 'function') {
        gr.ready(() => {
            gr.execute(key, {action}).then(resolve).catch(reject);
        });
        return;
    }
    // grecaptcha not loaded yet — inject the script ourselves
    const script = document.createElement('script');
    script.src = 'https://www.google.com/recaptcha/api.js?render=' + key;
    script.onerror = () => reject(new Error('Failed to load reCAPTCHA script'));
    script.onload = () => {
        const g = window.grecaptcha;
        if (!g) { reject(new Error('grecaptcha still undefined after script load')); return; }
        g.ready(() => {
            g.execute(key, {action}).then(resolve).catch(reject);
        });
    };
    document.head.appendChild(script);
})
"""

# Basic anti-detection init script
_STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
window.chrome = {runtime: {}, loadTimes: () => {}, csi: () => {}};
"""


class RecaptchaV3Solver:
    """Solves RecaptchaV3TaskProxyless tasks via headless Chromium."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None

    async def start(self) -> None:
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=self._config.browser_headless,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        log.info(
            "Playwright browser started (headless=%s)", self._config.browser_headless
        )

    async def stop(self) -> None:
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        log.info("Playwright browser stopped")

    async def solve(self, params: dict[str, Any]) -> dict[str, Any]:
        website_url = params["websiteURL"]
        website_key = params["websiteKey"]
        page_action = params.get("pageAction", "verify")

        last_error: Exception | None = None
        for attempt in range(self._config.captcha_retries):
            try:
                token = await self._solve_once(
                    website_url, website_key, page_action
                )
                return {"gRecaptchaResponse": token}
            except Exception as exc:
                last_error = exc
                log.warning(
                    "Attempt %d/%d failed for %s: %s",
                    attempt + 1,
                    self._config.captcha_retries,
                    website_url,
                    exc,
                )
                if attempt < self._config.captcha_retries - 1:
                    await asyncio.sleep(2)

        raise RuntimeError(
            f"Failed after {self._config.captcha_retries} attempts: {last_error}"
        )

    async def _solve_once(
        self, website_url: str, website_key: str, page_action: str
    ) -> str:
        assert self._browser is not None

        context = await self._browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1920, "height": 1080},
            locale="en-US",
        )

        page = await context.new_page()
        await page.add_init_script(_STEALTH_JS)

        # Diagnostics: main-frame navigations and navigations we blocked
        navigations: list[str] = []
        blocked: list[str] = []
        page.on(
            "framenavigated",
            lambda frame: navigations.append(frame.url)
            if frame == page.main_frame
            else None,
        )

        try:
            return await self._run(page, website_url, website_key, page_action, blocked)
        except Exception as exc:
            raise RuntimeError(
                f"{exc} [navigations={navigations[-6:]} blocked={blocked[-6:]}]"
            ) from exc
        finally:
            await context.close()

    async def _run(
        self, page, website_url: str, website_key: str, page_action: str,
        blocked: list[str],
    ) -> str:
        timeout_ms = self._config.browser_timeout * 1000

        # Serve a blank document for the initial websiteURL navigation instead
        # of the real page.
        # reCAPTCHA only checks the origin, and without the site's own scripts
        # nothing can reload or redirect the page mid-execute (e.g. antcpt.com
        # calls location.reload() after its own score check). Any other
        # main-frame navigation is aborted.
        served = False

        async def _serve_blank(route):
            nonlocal served
            request = route.request
            if not (request.is_navigation_request() and request.frame == page.main_frame):
                await route.continue_()
            elif not served:
                served = True
                await route.fulfill(
                    status=200,
                    content_type="text/html",
                    body="<!doctype html><html><head><title></title></head><body></body></html>",
                )
            else:
                blocked.append(request.url)
                await route.abort("aborted")

        await page.route("**/*", _serve_blank)
        await page.goto(website_url, wait_until="load", timeout=timeout_ms)

        # Simulate minimal human-like behaviour to improve score
        await page.mouse.move(400, 300)
        await asyncio.sleep(1)
        await page.mouse.move(600, 400)
        await asyncio.sleep(0.5)

        token = await self._evaluate_execute(page, website_key, page_action)

        if not isinstance(token, str) or len(token) < 20:
            raise RuntimeError(f"Invalid token received: {token!r}")

        log.info(
            "Got reCAPTCHA token for %s (len=%d)", website_url, len(token)
        )
        return token

    @staticmethod
    async def _evaluate_execute(page, website_key: str, page_action: str) -> Any:
        """Run _EXECUTE_JS, retrying if a navigation destroys the JS context."""
        for attempt in range(3):
            try:
                return await page.evaluate(_EXECUTE_JS, [website_key, page_action])
            except Exception as exc:
                if "Execution context was destroyed" not in str(exc) or attempt == 2:
                    raise
                log.info("Page navigated during evaluate, retrying after load")
                await page.wait_for_load_state("load")
