import re
from pathlib import Path
from html.parser import HTMLParser
import pytest

class DivCounterParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.open_divs = 0
        self.close_divs = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "div":
            self.open_divs += 1

    def handle_endtag(self, tag):
        if tag.lower() == "div":
            self.close_divs += 1

def test_dashboard_template_divs_are_balanced():
    """
    app/templates/dashboard.html must have balanced opening and closing <div> tags.
    """
    template_path = Path(__file__).resolve().parent.parent / "app" / "templates" / "dashboard.html"
    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = DivCounterParser()
    parser.feed(content)
    assert parser.open_divs == parser.close_divs, (
        f"Unbalanced <div> tags in dashboard.html: {parser.open_divs} opened vs {parser.close_divs} closed"
    )

def test_test_partners_contain_only_neutral_ids():
    """
    TEST_PARTNERS in app/main.py must contain ONLY test_partner_a, test_partner_b, and test_partner_c.
    Legacy IDs (partner_alpha, partner_beta, partner_gamma) must be removed.
    """
    from app.main import TEST_PARTNERS
    partner_ids = [p["partner_id"] for p in TEST_PARTNERS]
    assert partner_ids == ["test_partner_a", "test_partner_b", "test_partner_c"]
    assert "partner_alpha" not in partner_ids
    assert "partner_beta" not in partner_ids
    assert "partner_gamma" not in partner_ids
