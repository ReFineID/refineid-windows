#!/usr/bin/env python3
"""Automated Edge browser testing for card authentication on Windows.

Uses Microsoft Edge WebDriver (msedgedriver) to exercise mTLS client
certificate authentication against https://card.refineid.fi and Finnish
public identification portals.

Configures AutoSelectCertificateForUrls so Edge automatically selects the
matching client certificate without requiring manual dialog clicks.
"""

import argparse
import glob
import json
import os
import sys
import time

from selenium import webdriver
from selenium.webdriver.edge.options import Options
from selenium.webdriver.edge.service import Service


def find_msedgedriver() -> str | None:
    """Finds msedgedriver.exe on the system."""
    # Check WinGet package location
    user_profile = os.environ.get("USERPROFILE", "")
    winget_pattern = os.path.join(
        user_profile,
        "AppData",
        "Local",
        "Microsoft",
        "WinGet",
        "Packages",
        "*EdgeDriver*",
        "msedgedriver.exe",
    )
    matches = glob.glob(winget_pattern)
    if matches:
        return matches[0]

    # Check common locations
    candidates = [
        r"C:\Windows\System32\msedgedriver.exe",
        os.path.join(user_profile, "msedgedriver.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c

    # Check PATH
    for path_dir in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(path_dir, "msedgedriver.exe")
        if os.path.isfile(candidate):
            return candidate

    return None


def run_test(
    url: str,
    driver_path: str | None = None,
    headless: bool = True,
    screenshot_path: str = "edge_login_result.png",
    timeout: int = 15,
) -> dict:
    if not driver_path:
        driver_path = find_msedgedriver()

    if not driver_path or not os.path.isfile(driver_path):
        raise RuntimeError(
            f"msedgedriver.exe not found. Install via: winget install Microsoft.EdgeDriver, "
            f"or specify --driver <path>."
        )

    print(f"Using Edge WebDriver: {driver_path}")
    print(f"Target URL: {url}")
    print(f"Headless mode: {headless}")

    options = Options()
    if headless:
        options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1280,1024")
    options.add_argument("--ignore-certificate-errors")

    # Configure auto-selection of client certificates matching target
    auto_select_rule = json.dumps({"pattern": url, "filter": {}})
    options.add_experimental_option(
        "prefs",
        {
            "client_certificate": {
                "auto_select_certificate_for_urls": [auto_select_rule]
            }
        },
    )

    service = Service(executable_path=driver_path)
    driver = webdriver.Edge(service=service, options=options)

    try:
        driver.set_page_load_timeout(timeout)
        start_time = time.time()
        print(f"Navigating to {url}...")
        driver.get(url)
        elapsed = time.time() - start_time

        title = driver.title
        current_url = driver.current_url
        page_text = driver.find_element("tag name", "body").text

        # Ensure directory exists for screenshot
        screenshot_dir = os.path.dirname(screenshot_path)
        if screenshot_dir:
            os.makedirs(screenshot_dir, exist_ok=True)
        driver.save_screenshot(screenshot_path)
        print(f"Screenshot saved to: {screenshot_path}")

        # Check for card authentication status
        # Success markers:
        success_markers = [
            "Card holder",
            "Client Certificate",
            "Autentikoitu",
            "Authenticated",
            "Varmenne",
        ]
        # Unauthenticated / 403 markers:
        unauth_markers = [
            "Card login did not complete",
            "Client certificate missing",
            "403 Forbidden",
        ]

        auth_success = any(m.lower() in page_text.lower() for m in success_markers)
        auth_incomplete = any(m.lower() in page_text.lower() for m in unauth_markers)

        result = {
            "url": current_url,
            "title": title,
            "elapsed_seconds": round(elapsed, 2),
            "authenticated": auth_success,
            "incomplete": auth_incomplete,
            "screenshot": screenshot_path,
            "snippet": page_text[:300].replace("\n", " "),
        }

        print("\n--- Test Results ---")
        print(f"Title: {title}")
        print(f"Final URL: {current_url}")
        print(f"Elapsed: {result['elapsed_seconds']}s")
        print(f"Authenticated: {auth_success}")
        print(f"Incomplete/No-Cert: {auth_incomplete}")
        print(f"Snippet: {result['snippet']}")

        return result

    finally:
        driver.quit()


def main():
    parser = argparse.ArgumentParser(
        description="Run Edge WebDriver card authentication test on Windows"
    )
    parser.add_argument(
        "--url",
        default="https://card.refineid.fi",
        help="Target URL (default: https://card.refineid.fi)",
    )
    parser.add_argument(
        "--driver",
        default=None,
        help="Path to msedgedriver.exe",
    )
    parser.add_argument(
        "--no-headless",
        action="store_true",
        help="Run Edge with a visible UI window",
    )
    parser.add_argument(
        "--screenshot",
        default="edge_login_result.png",
        help="Path where screenshot should be saved",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Page load timeout in seconds (default: 15)",
    )

    args = parser.parse_args()
    try:
        result = run_test(
            url=args.url,
            driver_path=args.driver,
            headless=not args.no_headless,
            screenshot_path=args.screenshot,
            timeout=args.timeout,
        )
        sys.exit(0)
    except Exception as e:
        print(f"Error running Edge browser test: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
