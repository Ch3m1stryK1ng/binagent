"""Regression tests for finding extraction from Ghidra decompile payloads."""

import json

from pentestagent.agents.general_agent import GeneralAgent


def _make_agent_stub() -> GeneralAgent:
    agent = GeneralAgent.__new__(GeneralAgent)
    agent.findings = []
    agent._ghidra_available = True
    agent._required_pseudocode_targets = set()
    agent._viewed_pseudocode_functions = set()
    agent._log = lambda *args, **kwargs: None
    return agent


def test_extract_findings_from_ghidra_code_field():
    agent = _make_agent_stub()

    payload = {
        "name": "cuiGetInteger-08012368",
        "code": """
int cuiGetInteger(char *message)
{
  undefined1 auStack_30 [32];
  int local_10;
  int local_c;

  do {
    printf(message);
    local_c = scanf("%u",&local_10);
    if (local_c != 1) {
      scanf("%s",auStack_30);
    }
  } while (local_c != 1);
  return local_10;
}
""",
    }

    agent._extract_findings_from_tool_result(
        "mcp_ghidra-local_decompile_function",
        json.dumps(payload),
    )

    cwes = {f.get("cwe") for f in agent.findings}
    assert "CWE-120" in cwes
    assert "CWE-134" in cwes


def test_deduplicate_findings_by_evidence_and_location():
    agent = _make_agent_stub()

    findings = [
        {
            "cwe": "CWE-120",
            "title": "Unbounded scanf into buffer",
            "function": "cuiGetInteger-08012368",
            "address": "",
            "evidence": 'scanf("%s",auStack_30);',
            "rationale": "Unbounded %s format in scanf can overflow destination buffer.",
            "confidence": "high",
        },
        {
            "cwe": "CWE-120",
            "title": "",
            "function": "cuiGetInteger-08012368",
            "address": "",
            "evidence": 'scanf("%s", auStack_30);',
            "rationale": "same issue",
            "confidence": "medium",
        },
        {
            "cwe": "CWE-134",
            "title": "",
            "function": "",
            "address": "",
            "evidence": "printf(message) with untrusted message -> format string risk",
            "rationale": "Derived from analysis evidence.",
            "confidence": "medium",
        },
        {
            "cwe": "CWE-134",
            "title": "",
            "function": "",
            "address": "",
            "evidence": "printf(message) with untrusted message indicates format string risk",
            "rationale": "same issue repeated",
            "confidence": "medium",
        },
    ]

    deduped = agent._deduplicate_findings(findings)
    assert len(deduped) == 2
    assert any(f.get("cwe") == "CWE-120" for f in deduped)
    assert any(f.get("cwe") == "CWE-134" for f in deduped)


def test_does_not_extract_findings_from_plan_text():
    agent = _make_agent_stub()
    plan_text = (
        "PLAN:\n"
        "1. [Tool: notes] Build FINDINGS_JSON. Use precise CWEs: CWE-134, CWE-121, CWE-787.\n"
        "2. [Tool: finish] Summarize.\n"
    )
    agent._extract_findings_from_content(plan_text)
    assert agent.findings == []


def test_negated_vulnerability_statement_not_flagged():
    agent = _make_agent_stub()
    text = "No confirmed buffer overflow or format string vulnerabilities were identified."
    agent._extract_findings_from_content(text)
    assert agent.findings == []


def test_finding_status_confirmed_vs_suspicious():
    agent = _make_agent_stub()

    confirmed = agent._normalize_finding(
        {
            "cwe": "CWE-120",
            "title": "Unbounded scanf into buffer",
            "function": "cuiGetInteger",
            "evidence": 'scanf("%s", auStack_30);',
            "rationale": 'Unbounded "%s" format in scanf can overflow destination buffer.',
            "confidence": "high",
        }
    )
    suspicious = agent._normalize_finding(
        {
            "cwe": "CWE-134",
            "title": "Potential format string",
            "function": "",
            "evidence": "printf(message) with untrusted message indicates format string risk",
            "rationale": "Derived from analysis evidence.",
            "confidence": "medium",
        }
    )

    assert confirmed["finding_status"] == "confirmed"
    assert suspicious["finding_status"] == "suspicious"


def test_confirmation_request_detection():
    agent = _make_agent_stub()
    assert agent._is_confirmation_request("Please confirm so I can continue to Step 3.")
    assert agent._is_confirmation_request("I will execute Step 2 after you confirm.")
    assert not agent._is_confirmation_request("Proceeding to Step 3 now.")
