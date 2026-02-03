#!/usr/bin/env python3
"""
Validation script for ida_static_analyze.py
Tests that the generated IDAPython script has no syntax errors.
"""

import sys
import ast
import re

def extract_ida_script(source_file: str) -> str:
    """Extract the embedded IDAPython script from the generator."""
    with open(source_file, 'r') as f:
        content = f.read()

    # Find the script = f''' ... ''' block
    match = re.search(r"script = f'''(.+?)'''", content, re.DOTALL)
    if not match:
        print("[ERROR] Could not find embedded script in source")
        return None

    raw_script = match.group(1)

    # The script uses {{ and }} for literal braces in f-strings
    # Convert to actual braces for syntax validation
    script = raw_script.replace("{{", "{").replace("}}", "}")

    # Replace f-string placeholders with dummy values for syntax check
    # Use a simpler approach - just replace {anything} that's not a dict literal
    # First, protect dict literals by marking them
    script = re.sub(r'\{(\s*"[^"]+"\s*:\s*)', r'__DICT_START__\1', script)
    script = re.sub(r'\{(\s*\'[^\']+\'\s*:\s*)', r'__DICT_START__\1', script)

    # Now replace remaining f-string vars (simple identifiers)
    script = re.sub(r'\{([a-zA-Z_][a-zA-Z0-9_\.\'"\[\]]*)\}', r'"placeholder"', script)
    script = re.sub(r'\{([a-zA-Z_][a-zA-Z0-9_\.\'"\[\]]*:[^}]*)\}', r'"placeholder"', script)

    # Restore dict starts
    script = script.replace('__DICT_START__', '{')

    return script


def validate_python_syntax(script: str) -> tuple:
    """Validate Python syntax."""
    try:
        ast.parse(script)
        return True, None
    except SyntaxError as e:
        return False, e


def check_imports(script: str) -> list:
    """Check that all expected imports are present."""
    expected_imports = [
        'idc', 'idaapi', 'idautils', 'ida_funcs', 'ida_bytes',
        'ida_name', 'ida_xref', 'ida_ida', 'ida_segment',
        'ida_lines', 'ida_pro', 'ida_typeinf', 'ida_nalt', 'ida_loader'
    ]

    missing = []
    for imp in expected_imports:
        if f"import {imp}" not in script:
            missing.append(imp)

    return missing


def check_required_functions(script: str) -> list:
    """Check that all expected functions are defined."""
    required_functions = [
        'log', 'get_basic_info', 'apply_libc_prototypes',
        'get_cfunc', 'get_pseudocode_at_address', 'get_full_pseudocode',
        'rename_variables_in_function', 'get_disasm_context',
        'identify_input_source', 'get_callee_name',
        'analyze_call_for_overflow', 'analyze_call_for_format_string',
        'analyze_malloc_for_integer_overflow', 'track_free_sites',
        'find_uaf_patterns', 'scan_all_functions', 'deduplicate_findings',
        'assign_finding_ids', 'annotate_database', 'generate_why_explanation',
        'generate_findings_json', 'generate_evidence_md',
        'generate_pseudocode_export', 'save_database', 'main'
    ]

    missing = []
    for func in required_functions:
        if f"def {func}(" not in script:
            missing.append(func)

    return missing


def check_output_paths(script: str) -> list:
    """Verify output file paths are defined."""
    required_outputs = [
        'FINDINGS_JSON', 'EVIDENCE_MD', 'PSEUDOCODE_C', 'IDA_LOG'
    ]

    missing = []
    for output in required_outputs:
        if output not in script:
            missing.append(output)

    return missing


def check_log_markers(script: str) -> dict:
    """Check for required log markers."""
    markers = {
        '[DECOMP]': script.count('[DECOMP]'),
        '[COMMENT]': script.count('[COMMENT]'),
        '[RENAME]': script.count('[RENAME]'),
        '[TYPE]': script.count('[TYPE]'),
        '[STAGE]': script.count('[STAGE]'),
        '[CANDIDATE]': script.count('[CANDIDATE]'),
        '[UAF]': script.count('[UAF]'),
        '[OUTPUT]': script.count('[OUTPUT]'),
    }
    return markers


def main():
    source_file = "tools/ida_static_analyze.py"

    print("=" * 60)
    print("IDAPython Script Validator")
    print("=" * 60)
    print(f"\nSource: {source_file}\n")

    # Extract script
    print("[1] Extracting embedded script...")
    script = extract_ida_script(source_file)
    if not script:
        return 1
    print(f"    Extracted {len(script)} characters\n")

    # Check syntax
    print("[2] Validating Python syntax...")
    valid, error = validate_python_syntax(script)
    if valid:
        print("    [OK] Syntax is valid\n")
    else:
        print(f"    [ERROR] Syntax error: {error}\n")
        return 1

    # Check imports
    print("[3] Checking imports...")
    missing_imports = check_imports(script)
    if missing_imports:
        print(f"    [WARN] Missing imports: {missing_imports}")
    else:
        print("    [OK] All expected imports present\n")

    # Check functions
    print("[4] Checking required functions...")
    missing_functions = check_required_functions(script)
    if missing_functions:
        print(f"    [WARN] Missing functions: {missing_functions}")
    else:
        print("    [OK] All required functions defined\n")

    # Check outputs
    print("[5] Checking output path definitions...")
    missing_outputs = check_output_paths(script)
    if missing_outputs:
        print(f"    [WARN] Missing output paths: {missing_outputs}")
    else:
        print("    [OK] All output paths defined\n")

    # Check log markers
    print("[6] Checking log markers...")
    markers = check_log_markers(script)
    for marker, count in markers.items():
        status = "OK" if count > 0 else "MISSING"
        print(f"    {marker}: {count} occurrences [{status}]")
    print()

    # Summary
    print("=" * 60)
    all_ok = valid and not missing_functions and not missing_outputs
    if all_ok:
        print("VALIDATION PASSED")
        print("\nThe generated IDAPython script appears correct.")
        print("Expected outputs when run in IDA 9.x:")
        print("  - findings.json")
        print("  - evidence.md")
        print("  - pseudocode.c")
        print("  - ida_batch.log")
        print("  - database.i64")
    else:
        print("VALIDATION FAILED")
        print("\nPlease fix the issues above.")
    print("=" * 60)

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
