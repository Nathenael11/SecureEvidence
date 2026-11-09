# -*- coding: utf-8 -*-
"""
SecureEvidence: Forensic Court Certificate Generation Service
Author: Nathenael Ermias nathenaelermias13@gmail.com
"""

import html
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from backend.config import settings

def generate_court_certificate_html(record: Dict[str, Any], is_live: bool = False, verification_result: Optional[Dict[str, Any]] = None) -> str:
    """Generate self-contained official Forensic Evidence Integrity Certificate."""
    shield_svg = """<svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#1F6FB2" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="display:block;margin:0 auto 10px auto;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>"""
    shield_watermark_svg = """<svg width="340" height="340" viewBox="0 0 24 24" fill="none" stroke="#0B2A4A" stroke-width="1" stroke-linecap="round" stroke-linejoin="round" class="cert-watermark"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>"""
    case_id = html.escape(str(record.get("case_id", "INSA-CR-UNKNOWN")))
    incident = html.escape(str(record.get("incident_type") or "Cyber Threat Telemetry").replace("_", " "))
    target = html.escape(str(record.get("target_asset", "National-Core-Gateway")))
    block_num = html.escape(str(record.get("block_number", 1)))
    investigator = html.escape(str(record.get("investigator", "INSA Certified Forensic Examiner")))
    timestamp = html.escape(str(record.get("timestamp") or record.get("timestamp_utc") or datetime.now(timezone.utc).isoformat()))
    ev_hash = html.escape(str(record.get("evidence_hash", "")))
    raw_sig = record.get("officer_signature")
    sig = html.escape(str(raw_sig)) if raw_sig else "NOT SIGNED (demo)"
    ledger_mode = "LIVE PERMISSIONED BLOCKCHAIN" if is_live else "SQLITE HASH-CHAINED SOVEREIGN LEDGER"

    chain_id_val = record.get("chain_id") or (settings.CHAIN_ID if settings.CHAIN_MODE != "off" else None)
    contract_val = record.get("contract_address") or (settings.CONTRACT_ADDRESS if settings.CHAIN_MODE != "off" else None)
    tx_hash_val = record.get("tx_hash")
    has_real_tx = bool(tx_hash_val and str(tx_hash_val).startswith("0x"))
    chain_block_val = record.get("chain_block_number") if has_real_tx else None
    chain_mode_val = record.get("chain_mode") or settings.CHAIN_MODE
    is_sepolia = (str(chain_id_val) == "11155111" or chain_mode_val == "sepolia")
    explorer_base = (settings.EXPLORER_BASE_URL or "").rstrip("/") if is_sepolia else ""
    if has_real_tx and is_sepolia:
        eth_url = html.escape(f"{explorer_base or 'https://sepolia.etherscan.io'}/tx/{tx_hash_val}")
        bs_url = html.escape(f"https://eth-sepolia.blockscout.com/tx/{tx_hash_val}")
        explorer_display = f'<a href="{eth_url}" target="_blank" style="color:#1F6FB2;font-weight:600;margin-right:12px;text-decoration:underline;">Etherscan</a> <a href="{bs_url}" target="_blank" style="color:#1F6FB2;font-weight:600;text-decoration:underline;">Blockscout</a>'
    elif str(chain_id_val) == "31337" or chain_mode_val == "local":
        explorer_display = '<span style="color:#64748B;">Local node (Chain ID 31337 &mdash; private test RPC, not on public Etherscan)</span>'
    else:
        explorer_display = html.escape(str(tx_hash_val)) if tx_hash_val else "Local / N/A"

    chain_mode_disclaimer = ""

    is_authentic = verification_result.get("is_authentic", False) if verification_result else False
    is_superseded = record.get("superseded", False)
    if is_superseded:
        verdict_html = """
        <div class="verdict-banner" style="background:#FFF1F2;border:1px solid #FDA4AF;color:#BE123C;">
            <span>[!]</span>
            <span>RECORD SUPERSEDED: This evidence record has been revoked or superseded in the ledger history.</span>
        </div>"""
    elif is_authentic:
        verdict_html = """
        <div class="verdict-banner" style="background:#E3F3EA;border:1px solid #A8DEC0;color:#1E7B4F;">
            <span>[OK]</span>
            <span>INTEGRITY VERIFIED: Cryptographic fingerprint matches the anchored sovereign ledger record.</span>
        </div>"""
    else:
        verdict_html = """
        <div class="verdict-banner" style="background:#FFFBEB;border:1px solid #FCD34D;color:#B45309;">
            <span>[!]</span>
            <span>UNVERIFIED / PROTOTYPE RECORD: Cryptographic ledger verification not confirmed.</span>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Official Court Certificate — {case_id}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: #0B2A4A;
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            color: #16212E;
            padding: 30px 15px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}
        .no-print {{
            width: 100%;
            max-width: 820px;
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            margin-bottom: 16px;
        }}
        .btn {{
            background: #1F6FB2;
            color: #FFFFFF;
            border: none;
            padding: 9px 18px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }}
        .btn:hover {{ background: #185A92; }}
        .cert-container {{
            background: #FFFFFF;
            width: 100%;
            max-width: 820px;
            border: 4px double #0B2A4A;
            padding: 40px 48px;
            border-radius: 4px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            position: relative;
        }}
        .cert-watermark {{
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            opacity: 0.04;
            width: 400px;
            height: auto;
            pointer-events: none;
        }}
        .cert-header {{
            text-align: center;
            border-bottom: 2px solid #0B2A4A;
            padding-bottom: 18px;
            margin-bottom: 22px;
        }}
        .cert-logo {{
            width: 72px;
            height: auto;
            margin-bottom: 10px;
        }}
        .agency-title {{
            font-size: 13px;
            font-weight: 700;
            color: #0B2A4A;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .country-title {{
            font-size: 11px;
            color: #5B6B7D;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 2px;
        }}
        .doc-title {{
            font-size: 20px;
            font-weight: 800;
            color: #0B2A4A;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 14px;
        }}
        .framework-sub {{
            font-size: 10px;
            color: #5B6B7D;
            margin-top: 4px;
        }}
        .status-pill {{
            display: inline-block;
            background: #E4EFF9;
            color: #1F6FB2;
            border: 1px solid rgba(31,111,178,0.3);
            font-size: 10px;
            font-weight: 700;
            padding: 4px 12px;
            border-radius: 999px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 10px;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px 24px;
            background: #F8FAFD;
            border: 1px solid #D6DEE8;
            border-radius: 6px;
            padding: 16px 20px;
            margin: 20px 0;
            font-size: 12px;
        }}
        .meta-item {{
            display: flex;
            flex-direction: column;
            gap: 2px;
        }}
        .meta-label {{
            font-size: 10px;
            font-weight: 700;
            color: #5B6B7D;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .meta-val {{
            font-size: 13px;
            font-weight: 600;
            color: #16212E;
        }}
        .meta-val.mono {{
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;
            color: #0B2A4A;
        }}
        .crypto-box {{
            background: #FFFFFF;
            border: 1px solid #D6DEE8;
            border-left: 4px solid #1F6FB2;
            border-radius: 4px;
            padding: 12px 16px;
            margin-bottom: 12px;
        }}
        .crypto-label {{
            font-size: 10px;
            font-weight: 700;
            color: #1F6FB2;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }}
        .crypto-val {{
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;
            font-size: 11px;
            word-break: break-all;
            color: #0B2A4A;
            background: #F3F6FA;
            padding: 6px 8px;
            border-radius: 4px;
            border: 1px solid #E8EDF4;
        }}
        .verdict-banner {{
            background: #E3F3EA;
            border: 1px solid #A8DEC0;
            color: #1E7B4F;
            border-radius: 6px;
            padding: 12px 16px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 12px;
            font-weight: 700;
            margin: 18px 0;
        }}
        .cert-legal {{
            font-size: 11px;
            color: #5B6B7D;
            line-height: 1.6;
            margin-bottom: 24px;
            text-align: justify;
        }}
        .signatures-row {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 40px;
            margin-top: 36px;
            padding-top: 20px;
        }}
        .sig-block {{
            text-align: center;
        }}
        .sig-line {{
            border-bottom: 1px solid #16212E;
            margin-bottom: 8px;
        }}
        .sig-title {{
            font-size: 11px;
            font-weight: 700;
            color: #16212E;
        }}
        .sig-sub {{
            font-size: 10px;
            color: #5B6B7D;
            margin-top: 2px;
        }}
        @media print {{
            body {{ background: #FFFFFF !important; padding: 0 !important; }}
            .no-print {{ display: none !important; }}
            .cert-container {{ border: 2px solid #0B2A4A !important; box-shadow: none !important; padding: 24px 30px !important; }}
        }}
    </style>
</head>
<body>
    <div class="no-print">
        <button class="btn" onclick="window.print()">Print / Save as PDF</button>
    </div>

    <div class="cert-container">
        <div style="background:#FEF2F2;border:1px solid #DC2626;color:#991B1B;padding:8px 12px;border-radius:4px;font-size:11px;font-weight:700;text-align:center;letter-spacing:0.5px;margin-bottom:16px;">
            DEMONSTRATION PROTOTYPE &mdash; SECUREEVIDENCE LEDGER
        </div>
        {shield_watermark_svg}
        <div class="cert-header">
            {shield_svg}
            <div class="agency-title">SecureEvidence &mdash; Evidence Ledger</div>
            <div class="country-title">Digital Forensics &amp; Evidence Depository</div>
            <div class="doc-title">Forensic Evidence Integrity Certificate</div>
            <div class="framework-sub">Cryptographic Evidence Verification &amp; Tamper-Evident Ledger Audit</div>
            <div class="status-pill">{ledger_mode}</div>
        </div>

        <div class="meta-grid">
            <div class="meta-item">
                <span class="meta-label">Case Identifier:</span>
                <span class="meta-val mono">{case_id}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Incident Classification:</span>
                <span class="meta-val">{incident}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Target Asset / Node:</span>
                <span class="meta-val mono">{target}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Ledger Block Number:</span>
                <span class="meta-val mono">#{block_num}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Lead Forensic Investigator:</span>
                <span class="meta-val">{investigator}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Internal timestamp (not RFC 3161):</span>
                <span class="meta-val mono">{timestamp}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Chain ID:</span>
                <span class="meta-val mono">{chain_id_val if chain_id_val else 'Local / N/A'}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Contract Address:</span>
                <span class="meta-val mono" style="font-size:11px;word-break:break-all;">{contract_val if contract_val else 'N/A'}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Transaction Hash:</span>
                <span class="meta-val mono" style="font-size:11px;word-break:break-all;">{tx_hash_val if tx_hash_val else 'N/A'}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Chain Block Number:</span>
                <span class="meta-val mono">#{chain_block_val if chain_block_val else 'N/A'}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Explorer Link:</span>
                <span class="meta-val" style="font-size:11px;">{explorer_display}</span>
            </div>
        </div>

        <div style="background:#FFF9E6;border:1px solid #FFE082;color:#8D6E10;border-radius:4px;padding:8px 12px;font-size:11px;margin:12px 0;text-align:center;font-weight:600;">
            public test network, hashes only; not a legal timestamp
        </div>

        {chain_mode_disclaimer}

        <div class="crypto-box">
            <div class="crypto-label">SHA-256 Cryptographic Evidence Digest:</div>
            <div class="crypto-val">{ev_hash}</div>
        </div>

        <div class="crypto-box">
            <div class="crypto-label">Officer Digital Signature (SECP256R1 / ECDSA):</div>
            <div class="crypto-val">{sig}</div>
        </div>

        {verdict_html}

        <p class="cert-legal">
            This official document certifies that the aforementioned digital forensic payload was ingested, verified, and anchored into the SecureEvidence Forensic Evidence Ledger. The SHA-256 cryptographic digest and digital signature provide non-repudiation and tamper detection. Judicial admissibility remains subject to the court pursuant to applicable electronic evidence legal frameworks.
        </p>

        <div class="signatures-row">
            <div class="sig-block">
                <div class="sig-line"></div>
                <div class="sig-title">Certified Forensic Examiner</div>
                <div class="sig-sub">Digital Forensics Directorate</div>
            </div>
            <div class="sig-block">
                <div class="sig-line"></div>
                <div class="sig-title">Federal Registrar / Judiciary Auditor</div>
                <div class="sig-sub">Forensic Evidence Depository</div>
            </div>
        </div>
    </div>
</body>
</html>"""

