import os
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

def set_cell_background(cell, fill_hex):
    tcPr = cell._element.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), fill_hex)
    tcPr.append(shd)

def set_cell_margins(cell, top=120, bottom=120, left=160, right=160):
    tcPr = cell._element.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def add_heading_styled(doc, text, level):
    h = doc.add_heading(text, level=level)
    h.paragraph_format.space_before = Pt(14)
    h.paragraph_format.space_after = Pt(4)
    h.paragraph_format.keep_with_next = True
    for r in h.runs:
        r.font.name = "Calibri"
        if level == 1:
            r.font.size = Pt(16)
            r.font.bold = True
            r.font.color.rgb = RGBColor(0, 51, 102) # Navy
        elif level == 2:
            r.font.size = Pt(13)
            r.font.bold = True
            r.font.color.rgb = RGBColor(16, 124, 65) # Forest Green
        elif level == 3:
            r.font.size = Pt(11)
            r.font.bold = True
            r.font.color.rgb = RGBColor(60, 60, 60)
    return h

def add_callout(doc, title, body_text):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.autofit = False
    tbl.columns[0].width = Inches(6.5)
    cell = tbl.cell(0, 0)
    set_cell_background(cell, "F0F4F8")
    set_cell_margins(cell, top=140, bottom=140, left=180, right=180)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(4)
    r1 = p.add_run(title + "\n")
    r1.font.name = "Calibri"
    r1.font.bold = True
    r1.font.size = Pt(11)
    r1.font.color.rgb = RGBColor(0, 51, 102)
    
    r2 = p.add_run(body_text)
    r2.font.name = "Calibri"
    r2.font.size = Pt(10)
    r2.font.color.rgb = RGBColor(40, 40, 40)
    doc.add_paragraph().paragraph_format.space_after = Pt(4)

def format_table(tbl, col_widths, headers, data, alt_shading=True):
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.autofit = False
    
    hdr_cells = tbl.rows[0].cells
    for i, title in enumerate(headers):
        hdr_cells[i].width = col_widths[i]
        set_cell_background(hdr_cells[i], "003366")
        set_cell_margins(hdr_cells[i], top=100, bottom=100, left=120, right=120)
        p = hdr_cells[i].paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(0)
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(10)
        r.font.color.rgb = RGBColor(255, 255, 255)
        
    for row_idx, row_data in enumerate(data):
        row_cells = tbl.add_row().cells
        bg_color = "F9FBFC" if (alt_shading and row_idx % 2 == 1) else "FFFFFF"
        for col_idx, text in enumerate(row_data):
            row_cells[col_idx].width = col_widths[col_idx]
            set_cell_background(row_cells[col_idx], bg_color)
            set_cell_margins(row_cells[col_idx], top=80, bottom=80, left=120, right=120)
            p = row_cells[col_idx].paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after = Pt(0)
            r = p.add_run(str(text))
            r.font.name = "Calibri"
            r.font.size = Pt(9.5)
            r.font.color.rgb = RGBColor(40, 40, 40)
    doc_p = doc.add_paragraph()
    doc_p.paragraph_format.space_after = Pt(6)

doc = docx.Document()

# Page Margins
sections = doc.sections
for s in sections:
    s.top_margin = Inches(0.8)
    s.bottom_margin = Inches(0.8)
    s.left_margin = Inches(0.8)
    s.right_margin = Inches(0.8)

# Title Block
p_title = doc.add_paragraph()
p_title.paragraph_format.space_before = Pt(0)
p_title.paragraph_format.space_after = Pt(2)
r_t1 = p_title.add_run("Farmer Identity, Deduplication & Consent Architecture\n")
r_t1.font.name = "Calibri"
r_t1.font.size = Pt(22)
r_t1.font.bold = True
r_t1.font.color.rgb = RGBColor(0, 51, 102)

r_t2 = p_title.add_run("Privacy-Preserving DPI Concept Note, Comparative Analysis (Approaches 1 vs 2 vs Hybrid), GitHub Details & Safaricom Technical Guide\n")
r_t2.font.name = "Calibri"
r_t2.font.size = Pt(13)
r_t2.font.color.rgb = RGBColor(16, 124, 65)

r_meta = p_title.add_run("Version 2.0  |  October 2026  |  Final Architecture Release & Complete Implementation Guide")
r_meta.font.name = "Calibri"
r_meta.font.size = Pt(10)
r_meta.font.italic = True
r_meta.font.color.rgb = RGBColor(100, 100, 100)

doc.add_paragraph().paragraph_format.space_after = Pt(6)

# Revision History
rev_tbl = doc.add_table(rows=1, cols=3)
format_table(
    rev_tbl,
    [Inches(1.2), Inches(1.5), Inches(3.8)],
    ["Version", "Date", "Architectural Change"],
    [
        ["1.5", "16 October 2026", "Legacy HMAC Double-Hashing prototype; identified rainbow table vulnerability and consent coupling."],
        ["2.0", "27 October 2026", "Added comprehensive Comparative Architecture Analysis (Approach 1 vs Approach 2 vs Hybrid), RFC 9497 VOPRF implementation with secp256k1 DLEQ proofs, decoupled Attribution, Consent Registry with PEP, Store-and-Forward offline queue, GitHub repository reference, and Live Observability Dashboard."]
    ]
)

# Executive Summary
add_heading_styled(doc, "Executive Summary", 1)
p_sum = doc.add_paragraph()
p_sum.paragraph_format.line_spacing = 1.15
p_sum.paragraph_format.space_after = Pt(6)
p_sum.add_run(
    "OpenAgriNet (OAN) Kenya is a Digital Public Infrastructure (DPI) delivering agricultural advisory, input financing, and market access "
    "to smallholder farmers. In Kenya, multiple agricultural providers (e.g., One Acre Fund, DigiFarm by Safaricom, KTDA) frequently serve "
    "the same farmer. To measure genuine pilot success across 50,000 farmers without collecting personal data, OAN Kenya has evaluated "
    "three distinct architectural paradigms:\n\n"
    "1. Approach 1 (Legacy Double-Hashing): Simple but critically vulnerable to rainbow table attacks if the shared partner key is leaked.\n"
    "2. Approach 2 (Pure Decentralized Wallet / DID): Highly secure on paper, but completely unviable in rural Kenya where 70%+ of farmers use 2G basic feature phones.\n"
    "3. Approach 3 (The Hybrid VOPRF Architecture): Combines client-side blinding (cryptographic privacy) with an isolated HSM Evaluator (the 'Blind Notary'), "
    "an offline store-and-forward queue for field agents, and decoupled consent with automated Policy Enforcement (PEP).\n\n"
    "This document details the trade-offs, explains why the Hybrid Architecture was selected, provides visual analogies for business stakeholders, "
    "and gives complete engineering instructions and GitHub details for Safaricom."
)

# PART 1: BUSINESS ARCHITECTURE & COMPARATIVE ANALYSIS
add_heading_styled(doc, "PART 1: Business Architecture & Comparative Analysis", 1)

add_heading_styled(doc, "1. Evolution of Approaches: 1st vs 2nd vs Hybrid", 2)
p_comp = doc.add_paragraph()
p_comp.paragraph_format.line_spacing = 1.15
p_comp.paragraph_format.space_after = Pt(6)
p_comp.add_run(
    "To understand the architecture selected for OAN Kenya, we must examine the trade-offs between the three competing designs:"
)

comp_tbl = doc.add_table(rows=1, cols=4)
format_table(
    comp_tbl,
    [Inches(1.5), Inches(1.7), Inches(1.7), Inches(1.6)],
    ["Evaluation Criteria", "Approach 1: Double-Hashing", "Approach 2: Pure Decentralized (DID)", "Approach 3: Target Hybrid (VOPRF)"],
    [
        ["Core Cryptography", "HMAC-SHA256 with shared PARTNER_KEY + SERVER_KEY", "Client asymmetric keypairs stored in digital wallet", "RFC 9497 VOPRF over secp256k1 with DLEQ proofs"],
        ["Rainbow Table Resistance", "VULNERABLE: 200M Kenyan phones crackable in <2 min if key leaks", "IMMUNE: No centralized phone hash stored", "IMMUNE: HSM rate-limiting mathematically blocks offline brute force"],
        ["Feature Phone (2G / USSD) Compatibility", "HIGH: Compatible with basic phones", "ZERO: Requires smartphone with secure enclave / biometric wallet", "HIGH: Works via field agent apps and provider backends without smartphone"],
        ["Offline Rural Registration", "PARTIAL: No local zeroization or memory protection", "HIGH: Local wallet operations", "HIGH: Local encrypted SQLite with automatic memory shredding"],
        ["Consent Decoupling", "POOR: Consent tied to deletion; history lost on opt-out", "MEDIUM: Complex revocation credentials", "EXCELLENT: First-class mutable state; PEP blocks SMS while preserving identity"],
        ["Cross-Provider Deduplication", "YES: Single code across partners", "NO: Difficult across disconnected provider environments", "YES: Exact deterministic Token T derived across all providers"]
    ]
)

add_callout(
    doc,
    "Why Did We Choose the Hybrid Approach?",
    "Neither Approach 1 nor Approach 2 was acceptable for Kenya. Approach 1 was a data privacy time-bomb waiting to happen if a shared partner secret leaked. "
    "Approach 2 lived in an ivory tower that ignored the reality of rural African agriculture (feature phones, poor connectivity, lost SIMs). "
    "The Hybrid Approach bridges the gap: it delivers bank-grade cryptographic privacy (VOPRF) while maintaining 100% operational compatibility with rural field realities."
)

add_heading_styled(doc, "2. Explaining the Three Approaches in Plain English", 2)

p_app1 = doc.add_paragraph()
p_app1.paragraph_format.line_spacing = 1.15
p_app1.paragraph_format.space_after = Pt(6)
p_app1.add_run(
    "• Approach 1: The 'Shared Password' Analogy\n"
    "Imagine every bank teller in Kenya shares the exact same master key to scramble customer phone numbers. "
    "As long as the key is secret, numbers look scrambled. But there are only 200 million possible phone numbers in Kenya. "
    "If a single rogue employee or partner leaks that one key on the internet, an attacker can pre-calculate the code for all 200 million numbers "
    "in under 2 minutes (a rainbow table attack). Once created, the attacker simply matches the codes back to cleartext phone numbers, "
    "completely destroying the privacy of all 50,000 farmers.\n\n"
    "• Approach 2: The 'Smartphone Digital Wallet' Analogy\n"
    "In this model, the farmer carries an advanced digital identity wallet on an iPhone or Android phone, similar to Apple Wallet or European digital IDs. "
    "Whenever they meet a provider, their phone generates a zero-knowledge proof. "
    "While highly secure, this completely fails in rural Kenya. Over 70% of smallholder farmers use basic feature phones (Nokia 3310, USSD *384#) with no screens, "
    "no cryptographic chips, and no internet. If their phone battery dies, or if they lose their SIM card, their identity is permanently erased.\n\n"
    "• Approach 3: The Hybrid 'Blind Notary' Analogy\n"
    "The Hybrid Approach solves both problems. The farmer does not need a smartphone. The provider's field agent types the number into their tablet. "
    "The tablet seals the number in a cryptographic carbon envelope (Blinding). An independent Notary (Evaluator HSM) stamps the outside of the envelope "
    "with a master seal without opening it. The tablet peels off the outer cover, yielding a certified Token. "
    "There is NO shared partner key to leak. Even if a partner tries to brute-force 200M numbers, they cannot do it offline—they must ask the Notary, "
    "and the Notary rate-limits and blocks bulk scanning. It provides maximum cryptographic security while remaining 100% compatible with basic phones."
)

add_heading_styled(doc, "3. Critical Distinction: 'Pseudonymous Device' vs. Legal Identity", 2)
p_id = doc.add_paragraph()
p_id.paragraph_format.line_spacing = 1.15
p_id.paragraph_format.space_after = Pt(6)
p_id.add_run(
    "OAN Kenya explicitly does NOT claim that a phone-derived token is a definitive legal person identifier. In rural Kenya:\n"
    "1. Shared Household Phones: A husband, wife, and child often share a single mobile handset.\n"
    "2. Multiple SIM Cards: A farmer may switch between an Airtel SIM and a Safaricom M-Pesa line.\n"
    "3. Number Reassignment: Mobile numbers are recycled by telecom operators if dormant.\n\n"
    "Therefore, OAN terms this a 'Phone-Derived Pseudonymous Farmer Identity'. The architecture manages shared devices via co-holder profiles "
    "and handles number migrations through Token Alias Rotation without corrupting historical records."
)

add_heading_styled(doc, "4. The 5-Level Architecture Overview", 2)
p_lvl = doc.add_paragraph()
p_lvl.paragraph_format.line_spacing = 1.15
p_lvl.paragraph_format.space_after = Pt(6)
p_lvl.add_run(
    "The end-to-end identity, deduplication, and advisory workflow is structured into 5 decoupled operational levels:"
)

lvl_tbl = doc.add_table(rows=1, cols=3)
format_table(
    lvl_tbl,
    [Inches(1.5), Inches(2.2), Inches(2.8)],
    ["Level", "Architectural Layer", "Operational Function & Data Transformation"],
    [
        ["Level 1", "Client Input & Blinding", "Field app normalizes phone to E.164 (+254...). Blinds scalar curve point B = r * HashToGroup(x). Raw phone never leaves device."],
        ["Level 2", "Evaluator HSM (RFC 9497)", "Central HSM/KMS signs point Z = k * B and issues Fiat-Shamir DLEQ proof. Evaluator has zero access to phone or partner ID."],
        ["Level 3", "Client Unblinding & Finalize", "Client verifies DLEQ zero-knowledge proof, unblinds N = r⁻¹ * Z, and derives canonical 64-byte Token T and Storage Digest D."],
        ["Level 4", "Registry Entity & Attribution", "Registry maps D to stable FarmerEntity UUID. Attribution role (onboarder vs contributor) decoupled from identity. Consent recorded."],
        ["Level 5", "Observability & PEP Enforcement", "Live dashboard reflects verified metrics. Advisory dispatch services query Policy Enforcement Point (PEP) before sending SMS."]
    ]
)

# PART 2: TECHNICAL ARCHITECTURE
add_heading_styled(doc, "PART 2: Technical Architecture & Codebase Details", 1)

add_heading_styled(doc, "5. Cryptographic Engine (RFC 9497 VOPRF)", 2)
p_crypto = doc.add_paragraph()
p_crypto.paragraph_format.line_spacing = 1.15
p_crypto.paragraph_format.space_after = Pt(6)
p_crypto.add_run(
    "Implemented in app/crypto/voprf.py using 256-bit prime-order elliptic curve group arithmetic:\n\n"
    "1. Domain Separation: Input encoding enforces x = LP('oan-phone-dedup-v1') || LP(pilot_id) || LP(normalized_phone).\n"
    "   CRITICAL: Provider ID is strictly excluded from x to preserve cross-provider deduplication.\n"
    "2. HashToGroup: Maps x to valid curve point P = scalar_mult(SHA512(dst || x), G).\n"
    "3. Blinding: Generates random scalar r ∈ [1, N-1], computes B = r * P.\n"
    "4. Evaluator Signing: Computes Z = k * B, where k is the HSM private key.\n"
    "5. DLEQ Zero-Knowledge Proof: Proves log_G(K) == log_B(Z) == k using Fiat-Shamir heuristic.\n"
    "6. Unblinding: Client computes N = r⁻¹ * Z.\n"
    "7. Finalize: Generates canonical token T = HMAC-SHA512(N, LP('Finalize') || x).\n"
    "8. Storage Digest: D = HMAC-SHA256(SERVER_KEY, LP('oan-registry-v1') || LP(pilot_id) || LP(key_id) || T)."
)

add_heading_styled(doc, "6. Separation of Concerns Data Model", 2)
p_db = doc.add_paragraph()
p_db.paragraph_format.line_spacing = 1.15
p_db.paragraph_format.space_after = Pt(6)
p_db.add_run(
    "Implemented in app/models.py to guarantee strict decoupling of Identity, Attribution, and Consent:"
)

db_tbl = doc.add_table(rows=1, cols=3)
format_table(
    db_tbl,
    [Inches(1.8), Inches(2.2), Inches(2.5)],
    ["Table Name", "Primary Keys / Foreign Keys", "Architectural Role & Description"],
    [
        ["farmer_entity", "entity_id (UUID v4)", "Stable canonical person entity. Survives phone number rotations and consent state mutations."],
        ["token_alias", "alias_id, entity_id (FK), digest_d", "Binds multiple VOPRF token digests (e.g. SIM migrations) to a single stable entity."],
        ["partner_association", "association_id, entity_id (FK), partner_id", "Decoupled attribution layer. Stores roles (onboarder, primary, contributor) and discovery timestamps."],
        ["farmer_consent", "consent_id, entity_id (FK), partner_id", "First-class mutable consent state (ACTIVE, WITHDRAWN, PENDING), purpose scope, and audit timestamp."],
        ["audit_log", "id, action, entity_id (FK), partner_id, at", "Append-only tamper-evident compliance audit trail for data protection regulatory review."]
    ]
)

add_heading_styled(doc, "7. Consent Lifecycle & Policy Enforcement Point (PEP)", 2)
p_pep = doc.add_paragraph()
p_pep.paragraph_format.line_spacing = 1.15
p_pep.paragraph_format.space_after = Pt(6)
p_pep.add_run(
    "Consent must never be treated as a simple boolean flag. In OAN Kenya:\n"
    "• Consent Capture: Captured at POST /v1/consent/capture with fields: entity_id, partner_id, purpose, version, and channel.\n"
    "• Consent Withdrawal: Processed at POST /v1/consent/withdraw. Transitions status from ACTIVE to WITHDRAWN with withdrawal reason.\n"
    "• Policy Enforcement Point (PEP): Implemented at GET /v1/consent/check. Any OAN advisory service dispatching weather SMS, pest alerts, "
    "or credit scoring MUST query PEP prior to transmission. If status != ACTIVE, PEP immediately returns HTTP 403 Forbidden, halting the message."
)

add_heading_styled(doc, "8. Field-Ready Offline Store-and-Forward Queue", 2)
p_sf = doc.add_paragraph()
p_sf.paragraph_format.line_spacing = 1.15
p_sf.paragraph_format.space_after = Pt(6)
p_sf.add_run(
    "Rural Kenyan field agents frequently register farmers in areas with zero cellular connectivity. "
    "The OAN Client SDK (sdk/python/voprf_client.py) includes an OfflineStoreAndForwardQueue:\n"
    "1. Local Encrypted SQLite: Field app queues registration payload with local timestamp.\n"
    "2. Auto-Replay: When connectivity is restored, queue replays registrations in batches.\n"
    "3. First-to-Onboard Preservation: Registry respects original capture timestamp for attribution credit.\n"
    "4. Memory Shredding & Zeroization: Upon successful synchronization, raw phone records are overwritten with random bytes and permanently deleted from device storage."
)

add_heading_styled(doc, "9. Test Results & 3,000-Farmer Simulation Reconciliation", 2)
p_sim = doc.add_paragraph()
p_sim.paragraph_format.line_spacing = 1.15
p_sim.paragraph_format.space_after = Pt(6)
p_sim.add_run(
    "The prototype was tested against a comprehensive 3,000-farmer synthetic dataset in simulator/voprf_runner.py. "
    "The dataset includes cross-provider overlap, shared household phones, dual SIMs, and opt-out withdrawals:"
)

sim_tbl = doc.add_table(rows=1, cols=3)
format_table(
    sim_tbl,
    [Inches(2.5), Inches(1.5), Inches(2.5)],
    ["Simulation Metric", "Measured Value", "Reconciliation Status"],
    [
        ["Raw Registrations Sent", "3,540", "Processed across 3 test partners"],
        ["Unique Test Farmers Created", "3,000", "Baseline synthetic farmer population"],
        ["Household Shared Phones (Counted as 1)", "- 75", "Two farmers sharing one SIM handset"],
        ["Second SIM Cards (Counted as 2)", "+ 13", "Farmers holding dual mobile numbers"],
        ["Consents Withdrawn (Opt-Outs)", "35", "Strictly blocked at PEP (100% enforcement)"],
        ["Active Partner Registrations in Registry", "3,506", "Total active partner associations"],
        ["Canonical Unique Farmers in Registry", "2,939", "Exact mathematical reconciliation (0 error)"],
        ["Cross-Provider Overlap Rate", "16.17%", "567 farmers served by 2+ providers simultaneously"]
    ]
)

# PART 3: GITHUB REPOSITORY & SAFARICOM INSTRUCTIONS
add_heading_styled(doc, "PART 3: GitHub Details & Safaricom Technical Instructions", 1)

add_heading_styled(doc, "10. Official GitHub Repository & Release Details", 2)
p_gh = doc.add_paragraph()
p_gh.paragraph_format.line_spacing = 1.15
p_gh.paragraph_format.space_after = Pt(6)
p_gh.add_run(
    "All source code, cryptography, unit tests, and front-end observability templates are committed and pushed to GitHub:\n\n"
    "• Repository: https://github.com/nandakishore2404/kenya-farmer-hash-registry.git\n"
    "• Active Branch: fix/review-2026-10-15\n"
    "• Latest Commit: 96b665f (feat(dpi): add interactive mobile number tester, scenario suite at all architectural levels, and live dashboard metrics)\n"
    "• Architecture Version: 2.0 (RFC 9497 VOPRF + Decoupled Attribution + Consent Registry)"
)

add_heading_styled(doc, "11. Step-by-Step Instructions to Clone, Run & Verify", 2)
p_run = doc.add_paragraph()
p_run.paragraph_format.line_spacing = 1.15
p_run.paragraph_format.space_after = Pt(6)
p_run.add_run(
    "Step 1: Clone and Checkout Branch\n"
    "git clone https://github.com/nandakishore2404/kenya-farmer-hash-registry.git\n"
    "cd kenya-farmer-hash-registry\n"
    "git checkout fix/review-2026-10-15\n\n"
    "Step 2: Environment Setup with uv / python\n"
    "uv venv\n"
    "uv pip install -r requirements.txt cryptography\n"
    "# Or using standard python:\n"
    "python -m venv .venv\n"
    ".venv\\Scripts\\activate\n"
    "pip install -r requirements.txt cryptography\n\n"
    "Step 3: Start the OAN Registry & Evaluator Service\n"
    ".venv\\Scripts\\uvicorn app.main:app --host 127.0.0.1 --port 8008 --reload\n\n"
    "Step 4: Execute Test Suites\n"
    "• Prototype Tests: .venv\\Scripts\\python.exe prototype_voprf/tests/test_prototype.py (7/7 passing in 4.07s)\n"
    "• Integration Tests: .venv\\Scripts\\python.exe -m pytest tests/test_voprf_integration.py (4/4 passing)\n"
    "• 3,000-Farmer Simulator: .venv\\Scripts\\python.exe simulator/voprf_runner.py\n\n"
    "Step 5: Access Web Interfaces\n"
    "• Production Advisory Dashboard: http://localhost:8008/dashboard (User: admin / Password: dev_dashboard_password)\n"
    "• Interactive Developer Console: http://localhost:8008/dev/console (Live Mobile Tester & Scenario Suite)"
)

add_heading_styled(doc, "12. How to Use the Python Client SDK in Partner Applications", 2)
p_sdk = doc.add_paragraph()
p_sdk.paragraph_format.line_spacing = 1.15
p_sdk.paragraph_format.space_after = Pt(6)
p_sdk.add_run(
    "Partners (e.g. One Acre Fund, DigiFarm, KTDA) integrate using sdk/python/voprf_client.py:\n\n"
    "from sdk.python.voprf_client import OANFarmerVOPRFClient, normalise_kenyan_phone\n\n"
    "# 1. Initialize client with pinned Evaluator Public Key\n"
    "client = OANFarmerVOPRFClient(pilot_id='kenya-pilot', key_id='v1', evaluator_public_key=PUB_KEY)\n\n"
    "# 2. Blind phone number locally on field device (Clear phone never leaves!)\n"
    "x, B, r = client.prepare_blinded_registration('+254 712 345 678')\n\n"
    "# 3. Submit blinded point B to VOPRF Evaluator\n"
    "# POST /v1/evaluations -> returns Z and DLEQ proof\n\n"
    "# 4. Verify proof, unblind, and derive canonical Token T\n"
    "token_bytes = client.process_evaluation_response(x, B, r, eval_resp['evaluated_element'], eval_resp['proof'])\n\n"
    "# 5. Register finalized token with OAN Registry\n"
    "# POST /v1/farmers/token with base64(token_bytes)"
)

add_heading_styled(doc, "13. API Endpoint Specification Reference", 2)
api_tbl = doc.add_table(rows=1, cols=4)
format_table(
    api_tbl,
    [Inches(1.5), Inches(2.0), Inches(1.5), Inches(1.5)],
    ["Method", "Endpoint Path", "Caller Role", "Description"],
    [
        ["POST", "/v1/evaluations", "Field Apps / Partners", "VOPRF Evaluator: signs blinded points Z = k * B with DLEQ proof."],
        ["GET", "/v1/evaluator/public-key", "Public / Partners", "Returns pinned Evaluator Public Key K = k * G."],
        ["POST", "/v1/farmers/token", "Partners / Field Apps", "Registers 64-byte finalized Token T; resolves stable Entity UUID."],
        ["POST", "/v1/consent/capture", "Partners / Field Apps", "Captures farmer consent record for specific purpose and version."],
        ["GET", "/v1/consent/check", "OAN Advisory Services", "Policy Enforcement Point (PEP): returns ALLOW or BLOCK."],
        ["POST", "/v1/consent/withdraw", "Partners / USSD Channel", "Withdraws consent and triggers PEP blocking of advisory SMS."],
        ["GET", "/dashboard", "SAFIC / Donors", "Executive Advisory Telemetry Dashboard (HTTP Basic Auth)."],
        ["GET", "/dev/console", "Developers / Testers", "Interactive Mobile Number Tester and Scenario Suite."]
    ]
)

try:
    output_path = os.path.join(os.getcwd(), "OAN_Kenya_Farmer_Identity_Deduplication_Consent_Architecture_Final.docx")
    doc.save(output_path)
    print(f"Successfully generated updated document: {output_path}")
except Exception as e:
    print(f"Error saving: {e}")
