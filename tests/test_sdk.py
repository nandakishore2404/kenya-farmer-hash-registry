import json
import os
import subprocess
import pytest
from sdk.python.hasher import normalise_phone, hash_phone, InvalidPhone

TEST_VALUES_PATH = os.path.join(os.path.dirname(__file__), "..", "sdk", "test_values.json")
JS_TEST_PATH = os.path.join(os.path.dirname(__file__), "..", "sdk", "js", "test_hasher.js")

with open(TEST_VALUES_PATH, "r", encoding="utf-8") as f:
    TEST_CASES = json.load(f)

SAMPLE_KEY = "test_partner_secret_key_123"

def test_test_values_count():
    assert len(TEST_CASES) >= 20, f"Expected at least 20 test cases, got {len(TEST_CASES)}"

@pytest.mark.parametrize("case", TEST_CASES)
def test_python_sdk_cases(case):
    raw_input = case["input"]
    if case["valid"]:
        norm = normalise_phone(raw_input)
        assert norm == case["normalized"], f"Failed normalization for '{raw_input}' ({case.get('description')})"
        
        h = hash_phone(raw_input, SAMPLE_KEY)
        assert isinstance(h, str)
        assert len(h) == 64
        # Verify deterministic output
        assert h == hash_phone(case["normalized"], SAMPLE_KEY)
    else:
        with pytest.raises(InvalidPhone):
            normalise_phone(raw_input)

def test_js_sdk_via_node():
    """Run the Node.js test runner to ensure JS SDK passes identical test cases."""
    result = subprocess.run(
        ["node", JS_TEST_PATH],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0, f"Node.js tests failed:\n{result.stderr}\n{result.stdout}"
    assert "All" in result.stdout and "passed successfully" in result.stdout

def test_python_and_js_hash_equivalence():
    """Verify that Python and JavaScript produce the exact same HMAC hash for every valid test case."""
    for case in TEST_CASES:
        if case["valid"]:
            py_hash = hash_phone(case["input"], SAMPLE_KEY)
            
            # Execute inline node snippet to get JS hash
            js_code = f"""
            const {{ hashPhone }} = require('{JS_TEST_PATH.replace(os.sep, '/').replace('test_hasher.js', 'hasher.js')}');
            process.stdout.write(hashPhone({json.dumps(case['input'])}, '{SAMPLE_KEY}'));
            """
            res = subprocess.run(["node", "-e", js_code], capture_output=True, text=True)
            assert res.returncode == 0, f"Node execution error: {res.stderr}"
            js_hash = res.stdout.strip()
            
            assert py_hash == js_hash, f"Hash mismatch between Python ({py_hash}) and JS ({js_hash}) for '{case['input']}'"
