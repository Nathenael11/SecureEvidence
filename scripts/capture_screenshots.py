# -*- coding: utf-8 -*-
"""
Automated Screenshot Generation Script for SecureEvidence Documentation
Captures pixel-perfect 1280x900 screenshots reflecting the current web interface.
Author: Nathenael Ermias nathenaelermias13@gmail.com
"""

import os
import sys
import time
from playwright.sync_api import sync_playwright

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DOCS_SCREENSHOTS = os.path.join(BASE_DIR, "docs", "screenshots")
os.makedirs(DOCS_SCREENSHOTS, exist_ok=True)

SERVER_URL = "http://127.0.0.1:8910"

def main():
    print(f"[*] Connecting to running SecureEvidence instance at {SERVER_URL}...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 900}, device_scale_factor=1)
        page = context.new_page()

        # ----------------------------------------------------
        # Screenshot 1: Role-Based Access Control & Authentication
        # ----------------------------------------------------
        print("[*] Capturing 01_role_based_access.png...")
        page.goto(SERVER_URL, wait_until="networkidle")
        page.wait_for_timeout(1000)

        # Open Login Modal
        page.click("#btn-open-login")
        page.wait_for_selector("#login-modal:not(.hidden)", timeout=5000)
        # Click quick-fill demo role: Investigator
        page.click("#btn-role-investigator")
        page.wait_for_timeout(600)
        page.screenshot(path=os.path.join(DOCS_SCREENSHOTS, "01_role_based_access.png"))
        print("[+] Saved 01_role_based_access.png")

        # ----------------------------------------------------
        # Authenticate as demo_investigator
        # ----------------------------------------------------
        page.click("#lbl-btn-submit-login")
        page.wait_for_selector("#login-modal", state="hidden", timeout=10000)
        page.wait_for_selector("#user-chip:not(.hidden)", timeout=10000)
        page.wait_for_timeout(1200)

        # ----------------------------------------------------
        # Screenshot 2: AI Threat Triage & TreeSHAP Feature Explainability
        # ----------------------------------------------------
        print("[*] Capturing 02_threat_triage_and_explainability.png...")
        # Select Web Attack preset (loadScenario('sqli'))
        page.click("button[onclick*='sqli']")
        page.wait_for_timeout(500)
        page.click("#btn-detect")
        page.wait_for_selector("#res-category:has-text('Web Attack')", timeout=15000)
        page.wait_for_selector("#xai-attr-list .attr-item", timeout=5000)
        page.wait_for_timeout(1000)
        page.screenshot(path=os.path.join(DOCS_SCREENSHOTS, "02_threat_triage_and_explainability.png"))
        print("[+] Saved 02_threat_triage_and_explainability.png")

        # ----------------------------------------------------
        # Screenshot 3: Blockchain & Cryptographic Evidence Anchoring
        # ----------------------------------------------------
        print("[*] Capturing 03_blockchain_evidence_anchoring.png...")
        # Anchor evidence
        anchor_btn = page.locator("#btn-store-bc")
        if anchor_btn.is_enabled():
            anchor_btn.click()
            page.wait_for_timeout(2000)
        # Scroll slightly down to showcase TreeSHAP attributions, anchoring status, and stream pipeline card
        page.evaluate("window.scrollTo(0, 320)")
        page.wait_for_timeout(800)
        page.screenshot(path=os.path.join(DOCS_SCREENSHOTS, "03_blockchain_evidence_anchoring.png"))
        print("[+] Saved 03_blockchain_evidence_anchoring.png")

        # ----------------------------------------------------
        # Screenshot 4: High-Throughput Big Data Streaming Pipeline
        # ----------------------------------------------------
        print("[*] Capturing 04_big_data_streaming_pipeline.png...")
        page.evaluate("window.scrollTo(0, 0)")
        page.click("#nav-item-live-stream")
        page.wait_for_timeout(1200)
        page.screenshot(path=os.path.join(DOCS_SCREENSHOTS, "04_big_data_streaming_pipeline.png"))
        print("[+] Saved 04_big_data_streaming_pipeline.png")

        # ----------------------------------------------------
        # Screenshot 5: Cryptographic Tamper Detection & Avalanche Rejection
        # ----------------------------------------------------
        print("[*] Capturing 05_cryptographic_tamper_detection.png...")
        page.evaluate("window.scrollTo(0, 0)")
        page.click("#nav-item-integrity-verify")
        page.wait_for_timeout(1000)

        # Ensure editor has payload (fallback from ledgerRecordsMap if empty)
        page.evaluate("""
            const ed = document.getElementById('evidence-json-editor');
            if (!ed.value.trim()) {
                const keys = Object.keys(ledgerRecordsMap);
                if (keys.length > 0) {
                    const r = ledgerRecordsMap[keys[keys.length - 1]];
                    ed.value = JSON.stringify(r.raw_evidence || r, null, 2);
                    originalEvidencePayload = JSON.parse(ed.value);
                }
            }
        """)
        # Verify legitimate evidence first
        page.click("#btn-verify-ev")
        page.wait_for_timeout(1500)
        print("Verdict class after verify:", page.locator("#verdict-box").get_attribute("class"))

        # Click Simulate Bit Mutation
        page.click("#btn-tamper-json")
        page.wait_for_timeout(2000)
        print("Verdict class after tamper:", page.locator("#verdict-box").get_attribute("class"))

        # Scroll slightly so both the tampered payload and the red verdict box are in full view
        page.evaluate("window.scrollTo(0, 200)")
        page.wait_for_timeout(600)
        page.screenshot(path=os.path.join(DOCS_SCREENSHOTS, "05_cryptographic_tamper_detection.png"))
        print("[+] Saved 05_cryptographic_tamper_detection.png")

        # ----------------------------------------------------
        # Screenshot 6: FDRE Federal High Court Digital Evidence Certificate
        # ----------------------------------------------------
        print("[*] Capturing 06_court_evidence_certificate.png...")
        page.evaluate("window.scrollTo(0, 0)")
        # Open certificate modal with real Sepolia record (Record 8 or first available in ledgerRecordsMap)
        page.evaluate("""
            const keys = Object.keys(ledgerRecordsMap);
            const targetHash = ledgerRecordsMap['bac53c9eb55e3b94c216804c4318323ddbb79183e5a7d5e38251172e25f0b9fd'] 
                ? 'bac53c9eb55e3b94c216804c4318323ddbb79183e5a7d5e38251172e25f0b9fd' 
                : keys[keys.length - 1];
            openCertificateModalWithHash(targetHash);
        """)
        page.wait_for_selector("#cert-modal:not(.hidden)", timeout=5000)
        page.wait_for_timeout(1500)
        page.screenshot(path=os.path.join(DOCS_SCREENSHOTS, "06_court_evidence_certificate.png"))
        print("[+] Saved 06_court_evidence_certificate.png")

        browser.close()
        print("[+] All 6 screenshots successfully captured and updated!")

if __name__ == "__main__":
    main()
