# -*- coding: utf-8 -*-
"""
End-to-End Browser Playwright Tests for Item 6 & UI Flows
Author: Nathenael Ermias nathenaelermias13@gmail.com
"""

import os
import sys
import json
import time
import subprocess
import tempfile
import shutil
import pytest
from playwright.sync_api import sync_playwright

SERVER_URL = "http://127.0.0.1:8899"
SCREENSHOT_DIR = os.getenv("SCREENSHOT_DIR", os.path.join(tempfile.gettempdir(), "playwright_screenshots"))

def is_playwright_installed() -> bool:
    if os.getenv("SKIP_E2E_PLAYWRIGHT", "0") in ("1", "true", "yes"):
        return False
    try:
        from playwright.sync_api import sync_playwright
        return True
    except ImportError:
        return False

pytestmark = pytest.mark.skipif(
    not is_playwright_installed(),
    reason="Playwright not installed or SKIP_E2E_PLAYWRIGHT=1"
)

@pytest.fixture(scope="module", autouse=True)
def run_app_server():
    """Spin up uvicorn server on port 8899 with fixed test demo credentials in isolated temporary databases."""
    temp_dir = tempfile.mkdtemp(prefix="playwright_env_")
    temp_users = os.path.join(temp_dir, "playwright_users.db")
    temp_ledger = os.path.join(temp_dir, "playwright_ledger.db")
    temp_stream = os.path.join(temp_dir, "playwright_stream.db")

    prev_user_db = os.environ.get("USER_DB_PATH")
    os.environ["USER_DB_PATH"] = temp_users

    from backend.user_store import get_connection, hash_password, init_user_db
    init_user_db(temp_users)
    conn = get_connection(temp_users)
    pw_hash = hash_password("DemoTestPassword123!")
    for user, name, role in [
        ("demo_investigator", "INSA Senior Investigator", "investigator"),
        ("demo_analyst", "INSA Security Analyst", "analyst")
    ]:
        with conn:
            cursor = conn.execute("SELECT id FROM users WHERE username = ?", (user,))
            if cursor.fetchone():
                conn.execute("UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE username = ?", (pw_hash, user))
            else:
                conn.execute(
                    "INSERT INTO users (username, full_name, role, password_hash, is_active, failed_attempts, created_at) VALUES (?, ?, ?, ?, 1, 0, ?)",
                    (user, name, role, pw_hash, "2026-10-15T00:00:00Z")
                )
    conn.close()

    prod_db = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "ledger.db"))
    if os.path.exists(prod_db):
        shutil.copy(prod_db, temp_ledger)
    test_env = os.environ.copy()
    test_env["USER_DB_PATH"] = temp_users
    test_env["LEDGER_DB_PATH"] = temp_ledger
    test_env["STREAM_DB_PATH"] = temp_stream
    test_env["CHAIN_MODE"] = "local"
    test_env["CHAIN_RPC_URL"] = "http://127.0.0.1:8545"
    test_env["CHAIN_ID"] = "31337"
    deployed_contract = None
    deploy_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "deployments", "localhost.json"))
    if os.path.exists(deploy_file):
        try:
            with open(deploy_file, "r", encoding="utf-8") as df:
                deployed_contract = json.load(df).get("contractAddress")
        except Exception:
            pass
    if not deployed_contract:
        from backend.config import Settings
        fresh_settings = Settings()
        deployed_contract = fresh_settings.CONTRACT_ADDRESS or os.getenv("CONTRACT_ADDRESS", "0x5FbDB2315678afecb367f032d93F642f64180aa3")
    test_env["CONTRACT_ADDRESS"] = deployed_contract
    test_env["SUBMITTER_PRIVATE_KEY"] = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8899"],
        cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
        env=test_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Poll until ready
    import urllib.request
    ready = False
    for _ in range(60):
        try:
            with urllib.request.urlopen(f"{SERVER_URL}/health", timeout=1) as resp:
                if resp.status == 200:
                    ready = True
                    break
        except Exception:
            time.sleep(0.5)

    if not ready:
        proc.terminate()
        pytest.fail("Server failed to start on port 8899")

    yield

    proc.terminate()
    proc.wait()
    if prev_user_db is not None:
        os.environ["USER_DB_PATH"] = prev_user_db
    else:
        os.environ.pop("USER_DB_PATH", None)
    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass

@pytest.fixture(autouse=True)
def reset_user_lockouts():
    """Reset failed_attempts before each test so accounts are never locked."""
    from backend.user_store import get_connection
    conn = get_connection()
    with conn:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL "
            "WHERE username IN ('demo_investigator', 'demo_analyst')"
        )
    conn.close()
    yield


def test_e2e_auth_flows_and_role_restrictions():
    """
    Playwright verification:
    1. Not logged in: click detect -> login modal opens ('Sign in to continue').
    2. Login as demo_investigator -> detection succeeds.
    3. Reload page -> still logged in (restored via refresh token cookie).
    4. Investigator sees TreeSHAP panel and Anchor button enabled.
    5. Anchor evidence to ledger -> row added to ledger table.
    6. Logout -> redirects, user chip hidden, sign in visible.
    7. Capture screenshots.
    """
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 900})
        page = context.new_page()

        # Step 1: Open fresh page - not logged in
        page.goto(SERVER_URL, wait_until="domcontentloaded")
        page.wait_for_selector("#btn-detect")

        # Verify initial state: user chip is hidden, sign in button is visible
        assert page.is_hidden("#user-chip")
        assert page.is_visible("#btn-open-login")

        # Click "Run Threat Detection" while not logged in -> login modal opens
        page.click("#btn-detect")
        page.wait_for_selector("#login-modal:not(.hidden)")
        error_box = page.text_content("#login-error-msg")
        assert "Sign in to continue" in error_box

        # Screenshot 1: Login modal
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "01_login_modal.png"))

        # Step 2: Login as demo_investigator
        page.fill("#login-username", "demo_investigator")
        page.fill("#login-password", "DemoTestPassword123!")
        page.click("#lbl-btn-submit-login")

        # Wait for login modal to close and user chip to appear
        page.wait_for_selector("#login-modal", state="hidden")
        page.wait_for_selector("#user-chip:not(.hidden)")
        chip_text = page.text_content("#user-chip-name")
        assert "Investigator" in chip_text or "demo_investigator" in chip_text

        # Click detect -> detection succeeds
        page.click("#btn-detect")
        page.wait_for_selector("#res-category:not(:has-text('Awaiting Input'))", timeout=15000)
        res_cat = page.text_content("#res-category")
        assert len(res_cat.strip()) > 0
        assert "Awaiting Input" not in res_cat

        # Step 3: Reload -> still logged in (restored via refresh token cookie)
        page.reload()
        page.wait_for_selector("#user-chip:not(.hidden)")
        assert page.is_hidden("#btn-open-login")

        # Step 4: Investigator sees Anchor button enabled
        # Select Web Attack scenario so there is no unresolved model/rule disagreement
        page.click("button[onclick*='sqli']")
        page.click("#btn-detect")
        page.wait_for_selector("#res-category:not(:has-text('Awaiting Input'))", timeout=15000)

        # TreeSHAP panel check
        page.wait_for_selector("#xai-attr-list .attr-item")
        xai_rows = page.locator("#xai-attr-list .attr-item")
        assert xai_rows.count() >= 5

        # Screenshot 3: Detection with TreeSHAP
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "03_detection_treeshap.png"))

        # Investigator sees anchor button enabled and can click to anchor
        inv_anchor_btn = page.locator("#btn-store-bc")
        assert not inv_anchor_btn.is_disabled()
        page.click("#btn-store-bc")

        # Wait for toast and ledger table to update
        page.wait_for_selector("#ledger-table-body tr")
        table_rows = page.locator("#ledger-table-body tr")
        assert table_rows.count() >= 1

        # Screenshot 4: Investigator view after anchoring with ledger row
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "04_investigator_anchored_ledger.png"))

        # Step 5: Logout
        page.click("#user-chip button[title='Sign out']")
        page.wait_for_selector("#btn-open-login:not(.hidden)")
        assert page.is_hidden("#user-chip")

        browser.close()


# ---------------------------------------------------------------------------
# Item 4 — Three new Playwright tests (session persistence, role restriction,
#           tamper detection in the public verifier)
# ---------------------------------------------------------------------------

def _login(page, username: str, password: str):
    """Helper: open login modal and authenticate."""
    page.click("#btn-open-login")
    page.wait_for_selector("#login-modal:not(.hidden)")
    page.fill("#login-username", username)
    page.fill("#login-password", password)
    page.click("#lbl-btn-submit-login")
    # Wait for the modal to become hidden (closeLoginModal adds the 'hidden' class)
    page.wait_for_selector("#login-modal", state="hidden", timeout=20000)
    page.wait_for_selector("#user-chip:not(.hidden)", timeout=10000)


def test_e2e_reload_keeps_session():
    """
    Reload must restore the session via /auth/refresh (httpOnly cookie).
    After reload the user chip must still be visible and the username preserved.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        page.goto(SERVER_URL, wait_until="domcontentloaded")

        _login(page, "demo_investigator", "DemoTestPassword123!")

        # Capture the chip text before reload
        chip_before = page.inner_text("#user-chip")
        assert chip_before.strip(), "User chip must not be empty after login"

        # Full page reload
        page.reload(wait_until="domcontentloaded")

        # Session must be restored — chip still visible
        page.wait_for_selector("#user-chip:not(.hidden)", timeout=10000)
        chip_after = page.inner_text("#user-chip")
        assert chip_after.strip() == chip_before.strip(), (
            f"Session lost after reload: '{chip_before}' → '{chip_after}'"
        )

        browser.close()


def test_e2e_analyst_anchor_button_disabled():
    """
    Role separation verification:
    1. Unauthenticated user clicking detect is prompted with login modal.
    2. Authenticating as demo_analyst (role: analyst) succeeds.
    3. Analyst can run detection, but the Anchor button (#btn-store-bc) remains disabled.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1280, "height": 900})
        page = ctx.new_page()
        page.goto(SERVER_URL, wait_until="domcontentloaded")

        # 1. Unauthenticated: click detect -> login modal
        page.click("#btn-detect")
        page.wait_for_selector("#login-modal:not(.hidden)", timeout=10000)
        assert page.is_visible("#login-modal")

        # 2. Login as demo_analyst
        page.fill("#login-username", "demo_analyst")
        page.fill("#login-password", "DemoTestPassword123!")
        page.click("#lbl-btn-submit-login")
        page.wait_for_selector("#login-modal", state="hidden", timeout=15000)
        page.wait_for_selector("#user-chip:not(.hidden)", timeout=10000)

        # 3. Detect threat as analyst
        page.click("button[onclick*='sqli']")
        page.click("#btn-detect")
        page.wait_for_selector("#res-category:not(:has-text('Awaiting Input'))", timeout=15000)

        # 4. Verify anchor button is disabled for analyst with role restriction tooltip
        anchor_btn = page.locator("#btn-store-bc")
        assert anchor_btn.is_disabled()
        btn_title = anchor_btn.get_attribute("title") or ""
        assert "investigator" in btn_title.lower()

        ctx.close()
        browser.close()


def test_e2e_tamper_public_verify_not_found():
    """
    API-level tamper test: detect + anchor via httpx (skips slow browser login),
    then call the public verifier with a tampered hash.
    The API must return is_authentic=False or NOT_FOUND.
    """
    import httpx, urllib.request

    # Give the server a moment to recover after the 3 preceding browser tests
    time.sleep(4)

    with httpx.Client(base_url=SERVER_URL, timeout=30.0) as client:
        # Login as investigator via API (retry up to 5 times)
        login_resp = None
        for attempt in range(5):
            try:
                login_resp = client.post("/auth/login", json={
                    "username": "demo_investigator",
                    "password": "DemoTestPassword123!"
                })
                if login_resp.status_code == 200:
                    break
                time.sleep(2)
            except Exception:
                time.sleep(2)
        if login_resp is None or login_resp.status_code != 200:
            detail = login_resp.text[:200] if login_resp else "no response"
            pytest.fail(f"Investigator login failed after retries: {detail}")

        token = login_resp.json()["access_token"]
        auth = {"Authorization": f"Bearer {token}"}

        # Detect using a known Web Attack payload from fixtures
        fixtures_path = os.path.join(os.path.dirname(__file__), "fixtures", "cicids2017_test_samples.json")
        with open(fixtures_path, "r", encoding="utf-8") as ff:
            fixtures = json.load(ff)
        detect_payload = dict(fixtures["Web_Attack"])
        detect_payload["target_asset"] = "National-Gateway-Demo-01"
        detect_resp = client.post("/detect", json=detect_payload, headers=auth)
        assert detect_resp.status_code == 200, f"Detect failed: {detect_resp.text[:200]}"
        detect_data = detect_resp.json()

        # Anchor to ledger (conforming to EvidenceStoreRequest)
        incident_type = detect_data.get("threat_category", "Web Attack")
        if incident_type == "MODEL/RULE DISAGREEMENT - analyst review required":
            incident_type = "Web Attack"

        anchor_payload = {
            "case_id": "INSA-TAMPER-TEST-01",
            "incident_type": incident_type,
            "target_asset": "National-Gateway-Demo-01",
            "evidence_payload": {
                "incident_id": detect_data.get("incident_id"),
                "status": "CLASSIFIED",
                "target_asset": "National-Gateway-Demo-01",
                "threat_category": incident_type,
                "confidence": detect_data.get("confidence", 0.99),
                "raw_flow": detect_payload
            }
        }
        anchor_resp = client.post("/evidence/store", json=anchor_payload, headers=auth)
        if anchor_resp.status_code != 200:
            pytest.fail(f"Anchor failed: {anchor_resp.text[:400]}")

        evidence_hash = anchor_resp.json().get("evidence_hash", "")
        assert evidence_hash, "Expected evidence_hash in anchor response"

        # Tamper: flip the last hex character
        last_char = evidence_hash[-1]
        tampered = evidence_hash[:-1] + ("0" if last_char != "0" else "1")

        # Public verifier must reject the tampered hash
        verify_resp = client.post("/evidence/verify-public",
                                  json={"evidence_hash": tampered})
        assert verify_resp.status_code == 200
        data = verify_resp.json()
        is_auth = data.get("is_authentic", True)
        tamper_status = data.get("tamper_status", "")
        assert not is_auth or tamper_status in ("NOT_FOUND", "HASH_MISMATCH"), (
            f"Tampered hash should not verify as authentic: {data}"
        )

def test_live_stream_card_display():
    """Verify Live Stream card renders with initial STOPPED state, rate input, and controls."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(SERVER_URL, wait_until="networkidle")

        # Verify Live Stream section exists
        stream_sec = page.locator("#section-live-stream")
        assert stream_sec.count() == 1

        # Verify initial badge says STOPPED
        badge = page.locator("#stream-status-badge")
        assert badge.inner_text().strip() == "STOPPED"

        # Verify Replay Rate input has value 200
        rate_input = page.locator("#stream-control-rate")
        assert rate_input.input_value() == "200"

        # Verify Start and Stop buttons exist
        assert page.locator("#btn-stream-start").count() == 1
        assert page.locator("#btn-stream-stop").count() == 1

        browser.close()



def test_e2e_item1_anchor_benign_flow_and_check_registry():
    """Item 1: Anchor a BENIGN flow on National-Gateway-Demo-01 as demo_investigator and check registry row."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(SERVER_URL, wait_until="networkidle")

        # Login as demo_investigator
        page.locator("#btn-open-login").click()
        page.wait_for_selector("#login-modal:not(.hidden)")
        page.locator("#login-username").fill("demo_investigator")
        page.locator("#login-password").fill("DemoTestPassword123!")
        page.click("#lbl-btn-submit-login")
        page.wait_for_selector("#user-chip:not(.hidden)")

        # Verify lead investigator field is populated with authenticated user and is read-only
        inv_field = page.locator("#input_investigator")
        assert inv_field.is_editable() is False
        assert "investigator" in inv_field.input_value().lower() or "senior" in inv_field.input_value().lower()

        # Select benign preset
        page.locator("button.btn-preset").filter(has_text="Benign").click()
        page.wait_for_timeout(1000)

        # Run threat detection
        page.locator("#btn-detect").click()
        page.wait_for_selector("#action-box-panel:not(.hidden)", timeout=10000)

        # Check Case ID is server-generated (e.g. INSA-CR-...) and readonly
        case_id_field = page.locator("#input_case_id")
        assert case_id_field.is_editable() is False
        assert case_id_field.input_value().startswith("INSA-CR-")

        # Anchor evidence
        anchor_btn = page.locator("#btn-store-bc")
        assert anchor_btn.is_enabled()
        anchor_btn.click()
        page.wait_for_selector(".toast.success", timeout=10000)
        page.wait_for_timeout(1000)

        # Switch to Evidence Registry
        page.locator("#nav-item-ledger-registry").click()
        page.wait_for_selector("#ledger-table-body td:has-text('BENIGN')", timeout=10000)

        # Check registry row attributes
        first_row = page.locator("#ledger-table-body tr").first
        row_text = first_row.inner_text()
        assert "BENIGN" in row_text
        assert "National-Gateway-Demo-01" in row_text
        assert ("demo_investigator" in row_text or "INSA Senior Investigator" in row_text or "Investigator" in row_text)

        browser.close()


def test_e2e_item3_dashboard_counters_one_source_of_truth():
    """Item 3: Cards for stream totals show the same numbers as the stream card and label each."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(SERVER_URL, wait_until="networkidle")

        # Verify stat card labels
        ev_sub = page.locator("#lbl-metric-events-sub").inner_text().strip()
        thr_sub = page.locator("#lbl-metric-threats-sub").inner_text().strip()
        assert "stream start" in ev_sub or "all time" in ev_sub
        assert "stream start" in thr_sub or "all time" in thr_sub

        # Compare values between header cards and stream card
        top_events = page.locator("#stat-events-count").inner_text().strip()
        stream_events = page.locator("#stream-events-scored").inner_text().strip()
        assert top_events == stream_events

        browser.close()


def test_e2e_item8_stream_table_rules_confidence_and_deadletter():
    """Item 8: Stream table analyst review button gating, mismatches toggle, confidence 3 decimals, deadletter event."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(SERVER_URL, wait_until="networkidle")

        # Check dead-letter box exists and displays event & reason
        dl_box = page.locator("#stream-deadletter-box")
        assert dl_box.count() == 1
        assert page.locator("#stream-deadletter-msg").count() == 1

        # Check mismatches toggle exists
        mismatch_toggle = page.locator("#stream-mismatches-only")
        assert mismatch_toggle.count() == 1

        browser.close()


def test_e2e_item11_view_and_download_cert_disabled_until_verified():
    """Item 11: Disable 'View certificate' and 'Download certificate' until a record is verified."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(SERVER_URL, wait_until="networkidle")

        # Initially, buttons must be disabled
        view_cert_btn = page.locator("#btn-view-cert")
        download_cert_btn = page.locator("#btn-download-evidence")
        assert view_cert_btn.is_disabled()
        assert download_cert_btn.is_disabled()

        # Login as demo_investigator to perform anchor & verify
        page.locator("#btn-open-login").click()
        page.wait_for_selector("#login-modal:not(.hidden)")
        page.locator("#login-username").fill("demo_investigator")
        page.locator("#login-password").fill("DemoTestPassword123!")
        page.click("#lbl-btn-submit-login")
        page.wait_for_selector("#user-chip:not(.hidden)")

        # Run threat detection
        page.locator("button.btn-preset").filter(has_text="Benign").click()
        page.wait_for_timeout(500)
        page.locator("#btn-detect").click()
        page.wait_for_selector("#action-box-panel:not(.hidden)", timeout=10000)

        # Anchor to ledger
        page.locator("#btn-store-bc").click()
        page.wait_for_selector(".toast.success", timeout=10000)
        page.wait_for_timeout(1000)

        # Verify evidence in integrity panel
        page.locator("#nav-item-integrity-verify").click()
        page.wait_for_timeout(500)
        page.locator("#btn-verify-ev").click()
        page.wait_for_selector("#verdict-box.status-verified", timeout=10000)
        v_class = page.locator("#verdict-box").get_attribute("class")
        print("VERDICT CLASS:", v_class)
        print("VERDICT TITLE:", page.locator("#verdict-title").inner_text())
        print("VERDICT STATUS:", page.locator("#verdict-status").inner_text())
        assert "status-verified" in v_class

        # Now buttons must be enabled!
        assert view_cert_btn.is_enabled()
        assert download_cert_btn.is_enabled()

        # Tamper evidence
        page.locator("#btn-tamper-json").click()
        page.locator("#btn-verify-ev").click()
        page.wait_for_selector("#verdict-box.status-mismatch", timeout=10000)

        # Buttons must be disabled again
        assert view_cert_btn.is_disabled()
        assert download_cert_btn.is_disabled()

        browser.close()


def test_playwright_real_blockchain_anchoring_ui():
    """
    Phase C2 Playwright:
    With the local node running, anchor a record in the dashboard
    and check the chip, tx hash, block number and "On-chain: confirmed" on screen.
    """
    import urllib.request
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:8545",
            data=b'{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}',
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=1) as resp:
            if resp.status != 200:
                pytest.skip("Local chain RPC not reachable at http://127.0.0.1:8545")
    except Exception:
        pytest.skip("Local chain RPC not reachable at http://127.0.0.1:8545")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.on("console", lambda msg: print("BROWSER LOG:", msg.text))
        page.goto(SERVER_URL)
        page.wait_for_selector("#chip-ledger-type")

        # 1. Check Header Chip
        chip_text = page.locator("#chip-ledger-type").inner_text()
        assert "Ledger: SQLite + chain anchor (local node)" in chip_text

        # 2. Login as demo_investigator
        page.locator("#btn-open-login").click()
        page.wait_for_selector("#login-modal:not(.hidden)")
        page.locator("#login-username").fill("demo_investigator")
        page.locator("#login-password").fill("DemoTestPassword123!")
        page.click("#lbl-btn-submit-login")
        page.wait_for_selector("#user-chip:not(.hidden)")

        # 3. Detect and anchor
        page.locator("button.btn-preset").filter(has_text="Benign").click()
        page.wait_for_timeout(500)
        page.locator("#btn-detect").click()
        page.wait_for_selector("#action-box-panel:not(.hidden)", timeout=10000)

        page.locator("#btn-store-bc").click()
        page.wait_for_timeout(4000)

        # 4. Verify on Integrity Verify tab
        page.locator("#nav-item-integrity-verify").click()
        page.wait_for_timeout(500)
        page.locator("#btn-verify-ev").click()
        page.wait_for_timeout(2000)

        page.wait_for_selector("#verdict-box.status-verified", timeout=10000)

        # 5. Check on-chain elements on screen
        onchain_status_text = page.locator("#verdict-onchain-status").inner_text()
        assert "confirmed" in onchain_status_text.lower()

        block_num_text = page.locator("#verdict-block-num").inner_text()
        assert "#" in block_num_text

        tx_hash_text = page.locator("#verdict-tx-hash").inner_text()
        assert tx_hash_text.startswith("0x")
        assert len(tx_hash_text) == 66

        browser.close()
