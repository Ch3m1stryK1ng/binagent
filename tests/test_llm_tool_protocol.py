"""Tests for LLM tool-call protocol message sanitization."""

from pentestagent.llm.llm import sanitize_tool_protocol_messages


def test_drops_orphan_tool_message():
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "tool", "tool_call_id": "orphan", "content": "result"},
        {"role": "user", "content": "continue"},
    ]

    sanitized = sanitize_tool_protocol_messages(messages)

    assert sanitized == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "continue"},
    ]


def test_keeps_valid_assistant_tool_pair():
    messages = [
        {"role": "system", "content": "sys"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "x", "arguments": "{}"},
                }
            ],
        },
        {"role": "tool", "tool_call_id": "call_1", "content": "ok"},
    ]

    sanitized = sanitize_tool_protocol_messages(messages)

    assert sanitized == messages


def test_summary_truncation_pattern_is_sanitized():
    # Simulate memory output where the assistant tool_call turn was summarized
    # away but a trailing tool message remained in the recent window.
    messages = [
        {"role": "system", "content": "Previous conversation summary:\n..."},
        {"role": "tool", "tool_call_id": "pre_60", "content": "preflight output"},
        {"role": "user", "content": "analyze next"},
    ]

    sanitized = sanitize_tool_protocol_messages(messages)

    assert sanitized == [
        {"role": "system", "content": "Previous conversation summary:\n..."},
        {"role": "user", "content": "analyze next"},
    ]
