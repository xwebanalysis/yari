#!/usr/bin/env python3
"""Yari browser smoke test (Playwright, real Chromium).

Validates the signal-based (zoneless-safe) state contract end to end:

  1. The shell reports BACKEND ONLINE without any interaction (async HTTP).
  2. UI discovery renders the results section without extra clicks.
  3. The endpoint table renders on navigation with rest / graphql / js_crawl
     rows and the signal-backed protocol/search filters actually filter.
  4. A safe fuzz run renders requests + findings, and the auth test (with a
     pasted JWT) renders its tests table and findings.
  5. History lists persisted rows on entry, exports JSON/CSV, and OPEN loads
     the async detail.
  6. The EN/ES toggle re-renders labels while keeping loaded data.
  7. No console errors and no uncaught page errors.

Requirements:
  * `./yari.sh local` already running (frontend :4250, backend :8050)
  * Playwright + Chromium available in the interpreter running this script

Usage:
  python e2e/browser_smoke.py [--frontend http://127.0.0.1:4250]
                              [--fixture-port 8105] [--no-fixture] [--headed]

Exit code 0 means every check passed.
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import Page, TimeoutError as PlaywrightTimeoutError, sync_playwright

HERE = Path(__file__).resolve().parent
FIXTURE_SCRIPT = HERE / "fixture_server.py"


class CheckFailure(AssertionError):
    pass


def log(message: str) -> None:
    print(f"[yari-smoke] {message}", flush=True)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)
    log(f"PASS {message}")


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def wait_text(page: Page, selector: str, needle: str, timeout: int = 20000) -> None:
    try:
        page.wait_for_function(
            "([selector, needle]) => "
            "([...document.querySelectorAll(selector)].map((el) => el.textContent).join(' '))"
            ".includes(needle)",
            arg=[selector, needle],
            timeout=timeout,
        )
    except PlaywrightTimeoutError as exc:
        actual = page.locator(selector).first.text_content()
        raise CheckFailure(
            f"timed out waiting for {needle!r} in {selector!r} (actual: {actual!r})"
        ) from exc


def b64url(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def make_test_jwt() -> str:
    """A decodable alg=none JWT so the auth test has deterministic findings."""
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "yari-e2e", "role": "admin"}
    return f"{b64url(header)}.{b64url(payload)}.e2e-signature"


def run_checks(page: Page, frontend: str, fixture_url: str) -> list[str]:
    evidence: list[str] = []

    # ── 1. shell health, no clicks ────────────────────────────────────────
    page.goto(frontend + "/", wait_until="domcontentloaded")
    wait_text(page, ".status-label", "BACKEND ONLINE", timeout=20000)
    check(page.locator(".nav-link").count() == 5, "top navigation rendered")
    evidence.append("shell: [BACKEND ONLINE] rendered without interaction")

    # ── 2. UI discovery (REST sync path) ──────────────────────────────────
    page.uncheck("input[name='live']")
    page.fill("#target-input", fixture_url)
    page.click("button[type='submit']")
    page.wait_for_selector(".results-section", timeout=45000)
    values = [
        (node.text_content() or "").strip()
        for node in page.locator(".results-section .metric-value").all()
    ]
    check(len(values) >= 2, f"discover: metric cards rendered without clicks ({values})")
    check(int(values[0]) >= 5, f"discover: endpoints discovered ({values[0]})")
    check(int(values[1]) >= 1, f"discover: findings reported ({values[1]})")
    evidence.append(f"discover: {values[0]} endpoint(s), {values[1]} finding(s) — no clicks")

    # ── 3. endpoint table + filters ───────────────────────────────────────
    page.click("a.nav-link:has-text('ENDPOINTS')")
    wait_text(page, "h1", "ENDPOINT MAP", timeout=10000)
    page.wait_for_selector(".table-scroll table tbody tr", timeout=20000)
    table_text = page.locator(".table-scroll table").inner_text()
    check("/api/v1/users" in table_text, "endpoints: REST path from openapi.json listed")
    check("/graphql" in table_text, "endpoints: GraphQL path listed")
    check("js_crawl" in table_text, "endpoints: js_crawl source listed")
    check("openapi" in table_text, "endpoints: openapi source listed")
    check(
        page.locator(".tag-protocol-graphql").count() >= 1,
        "endpoints: graphql protocol tag rendered",
    )
    total_rows = page.locator(".table-scroll table tbody tr").count()

    # Signal-backed filters (regression: computed must depend on signals).
    page.click("button.chip:has-text('rest')")
    page.wait_for_function(
        "() => document.querySelectorAll('.tag-protocol-graphql').length === 0",
        timeout=10000,
    )
    rest_rows = page.locator(".table-scroll table tbody tr").count()
    check(
        rest_rows >= 4 and rest_rows < total_rows,
        f"endpoints: 'rest' chip filters table ({rest_rows}/{total_rows} rows)",
    )
    check(
        page.locator(".tag-protocol-rest").count() == rest_rows,
        "endpoints: filtered rows are all rest",
    )
    page.fill(".search-field", "users")
    page.wait_for_function(
        "() => { const rows = [...document.querySelectorAll('.table-scroll table tbody tr')];"
        " return rows.length > 0 && rows.every((r) => r.textContent.includes('/users')); }",
        timeout=10000,
    )
    filtered_rows = page.locator(".table-scroll table tbody tr").count()
    check(
        0 < filtered_rows < rest_rows,
        f"endpoints: search filter narrows the table ({filtered_rows} rows)",
    )
    page.fill(".search-field", "")
    page.wait_for_function(
        f"() => document.querySelectorAll('.table-scroll table tbody tr').length === {rest_rows}",
        timeout=10000,
    )
    page.click("button.chip:has-text('all')")
    evidence.append(
        f"endpoints: {total_rows} rows (rest/graphql/js_crawl); filters rest={rest_rows}, "
        f"search users={filtered_rows}"
    )

    # ── 4. safe fuzzing ───────────────────────────────────────────────────
    page.click("a.nav-link:has-text('FUZZING')")
    wait_text(page, "h1", "SAFE FUZZING", timeout=10000)
    page.wait_for_selector(".picker-list .picker-item", timeout=20000)
    page.click(".picker-actions button:has-text('CLEAR')")
    # The checkbox state is applied by change detection; wait for the DOM to
    # settle before checking a specific endpoint (zoneless scheduling).
    page.wait_for_function(
        "() => document.querySelectorAll('.picker-item input:checked').length === 0",
        timeout=10000,
    )
    echo_item = page.locator(".picker-item", has_text="/api/echo").first
    echo_item.locator("input[type='checkbox']").check()
    page.wait_for_function(
        "() => document.querySelectorAll('.picker-item input:checked').length === 1",
        timeout=10000,
    )
    page.click("button:has-text('RUN FUZZ')")
    page.wait_for_selector(".results", timeout=60000)
    page.wait_for_selector(".results .metric-value", timeout=10000)
    fuzz_values = [
        (node.text_content() or "").strip()
        for node in page.locator(".results .metric-value").all()
    ]
    check(int(fuzz_values[0]) >= 1, f"fuzz: requests sent ({fuzz_values[0]})")
    findings = page.locator(".results .finding-row")
    check(findings.count() >= 1, f"fuzz: {findings.count()} finding(s) rendered")
    check("EVIDENCE" in page.locator(".results").inner_text(), "fuzz: evidence block present")
    evidence.append(
        f"fuzz(safe) /api/echo: {fuzz_values[0]} request(s), {findings.count()} finding(s)"
    )

    # ── 5. auth test with a pasted JWT ────────────────────────────────────
    page.click("a.nav-link:has-text('AUTH')")
    wait_text(page, "h1", "AUTH TESTING", timeout=10000)
    page.wait_for_selector("#token-input", timeout=20000)
    page.fill("#token-input", make_test_jwt())
    page.click("button:has-text('RUN AUTH TEST')")
    page.wait_for_selector(".results table tbody tr", timeout=45000)
    test_rows = page.locator(".results table tbody tr").count()
    check(test_rows >= 1, f"auth: {test_rows} test row(s) rendered")
    check(
        page.locator(".results .sev-critical").count() >= 1,
        "auth: alg=none JWT flagged as critical",
    )
    auth_findings = page.locator(".results .finding-row").count()
    check(auth_findings >= 1, f"auth: {auth_findings} finding(s) rendered")
    evidence.append(
        f"auth-test: {test_rows} test(s), {auth_findings} finding(s), critical flag visible"
    )

    # ── 6. history, exports and async detail ──────────────────────────────
    page.click("a.nav-link:has-text('HISTORY')")
    wait_text(page, "h1", "ANALYSIS HISTORY", timeout=10000)
    page.wait_for_selector("table tbody tr", timeout=20000)
    rows = page.locator("table tbody tr")
    check(rows.count() >= 1, "history: rows render on entry without clicks")
    fixture_row = page.locator("table tbody tr", has_text="127.0.0.1:8105").first
    try:
        fixture_row.wait_for(state="visible", timeout=20000)
    except Exception:
        pass
    check(fixture_row.count() >= 1, "history: fixture analysis row present")

    with page.expect_download(timeout=20000) as json_download:
        fixture_row.locator("button:has-text('JSON')").click()
    check(
        json_download.value.suggested_filename.endswith(".json"),
        f"history: JSON export ({json_download.value.suggested_filename})",
    )
    with page.expect_download(timeout=20000) as csv_download:
        fixture_row.locator("button:has-text('CSV')").click()
    check(
        csv_download.value.suggested_filename.endswith(".csv"),
        f"history: CSV export ({csv_download.value.suggested_filename})",
    )

    # Reload: the workspace is in-memory, so this exercises async list loading
    # from scratch and then the async OPEN -> detail path.
    page.goto(frontend + "/history", wait_until="domcontentloaded")
    page.wait_for_selector("table tbody tr", timeout=20000)
    reloaded_rows = page.locator("table tbody tr").count()
    check(reloaded_rows >= 1, "history: rows load asynchronously after reload")
    first_row = page.locator("table tbody tr", has_text="127.0.0.1:8105").first
    first_row.locator("button:has-text('OPEN')").click()
    page.wait_for_selector(".detail", timeout=20000)
    wait_text(page, ".detail", "ANALYSIS DETAIL", timeout=10000)
    check(
        page.locator(".detail app-metric-card").count() >= 4,
        "history: OPEN renders the async detail view",
    )
    evidence.append(
        f"history: {reloaded_rows} row(s) after reload; JSON/CSV exports; async detail"
    )

    # ── 7. EN/ES toggle keeps data ────────────────────────────────────────
    fixture_rows_before = page.locator("table tbody tr", has_text="127.0.0.1:8105").count()
    findings_before = page.locator(".detail app-finding-list").count()
    page.click(".lang-toggle-btn")
    wait_text(page, "h1", "HISTORIAL", timeout=10000)
    check(
        page.locator("table tbody tr", has_text="127.0.0.1:8105").count()
        == fixture_rows_before
        and fixture_rows_before >= 1,
        "i18n: EN->ES keeps history rows (data preserved)",
    )
    check(
        page.locator(".detail app-finding-list").count() == findings_before,
        "i18n: EN->ES keeps detail findings (data preserved)",
    )
    page.click(".lang-toggle-btn")
    wait_text(page, "h1", "HISTORY", timeout=10000)
    evidence.append(f"i18n: EN/ES toggle preserved {fixture_rows_before} fixture row(s)")

    # ── 8. live WebSocket discovery (signal updates from socket callbacks) ─
    page.click("a.nav-link:has-text('DISCOVER')")
    wait_text(page, "h1", "API DISCOVERY", timeout=10000)
    page.check("input[name='live']")
    page.fill("#target-input", fixture_url)
    page.click("button[type='submit']")
    wait_text(page, ".terminal-body", "COMPLETED", timeout=60000)
    page.wait_for_selector(".results-section", timeout=20000)
    live_lines = page.locator(".terminal-line").count()
    check(live_lines >= 3, f"live ws: {live_lines} terminal line(s) rendered")
    evidence.append(f"live ws discovery: {live_lines} terminal line(s)")

    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description="Yari browser smoke test")
    parser.add_argument("--frontend", default="http://127.0.0.1:4250")
    parser.add_argument("--fixture-port", type=int, default=8105)
    parser.add_argument("--no-fixture", action="store_true", help="use an external fixture")
    parser.add_argument("--headed", action="store_true", help="run Chromium with a window")
    args = parser.parse_args()

    fixture_url = f"http://127.0.0.1:{args.fixture_port}"
    fixture_process: subprocess.Popen | None = None

    if not args.no_fixture and not port_open(args.fixture_port):
        log(f"starting fixture on {fixture_url}")
        fixture_process = subprocess.Popen(
            [sys.executable, str(FIXTURE_SCRIPT), str(args.fixture_port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        for _ in range(50):
            if port_open(args.fixture_port):
                break
            time.sleep(0.1)
        else:
            log("fixture did not come up")
            return 2

    if not port_open(4250) and "4250" in args.frontend:
        log(f"frontend not reachable at {args.frontend}; run ./yari.sh local first")
        return 2

    console_errors: list[str] = []
    page_errors: list[str] = []
    evidence: list[str] = []

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=not args.headed)
            context = browser.new_context(accept_downloads=True)
            page = context.new_page()
            page.on(
                "console",
                lambda message: console_errors.append(message.text)
                if message.type == "error"
                else None,
            )
            page.on("pageerror", lambda error: page_errors.append(str(error)))

            try:
                evidence = run_checks(page, args.frontend, fixture_url)
            finally:
                context.close()
                browser.close()
    finally:
        if fixture_process is not None:
            fixture_process.terminate()
            try:
                fixture_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                fixture_process.kill()

    check(not console_errors, f"console errors empty (got {console_errors[:3]})")
    check(not page_errors, f"page errors empty (got {page_errors[:3]})")

    print()
    print("=" * 72)
    print("YARI BROWSER SMOKE: OK")
    for line in evidence:
        print(f"  - {line}")
    print("  - console/page errors: empty")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CheckFailure as failure:
        log(f"FAIL {failure}")
        raise SystemExit(1)
