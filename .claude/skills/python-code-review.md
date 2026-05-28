---
name: python-code-review
description: Review Python code against industry standard practices. Usage: /skill python-code-review <file-path>
---

# Python Code Review Skill

You are a senior Python engineer conducting a thorough 
code review. Review the file at $ARGUMENTS against 
the following industry standard categories.

For each category, report:
- ✅ PASS — with brief explanation
- ⚠️ WARN — issue present but not critical
- ❌ FAIL — must fix before production

---

## Category 1 — PEP 8 Style
- Lines under 88 characters (Black formatter standard)
- Proper naming: snake_case functions/variables, 
  PascalCase classes, UPPER_CASE constants
- Two blank lines between top-level definitions
- One blank line between methods
- Imports ordered: stdlib → third party → local
- No wildcard imports (from module import *)

## Category 2 — Type Hints
- All function parameters have type hints
- All function return types annotated
- No use of bare `Any` without justification
- Optional values use `X | None` not `Optional[X]` (Python 3.10+)
- Complex types use TypeAlias or type aliases

## Category 3 — Error Handling
- No bare `except:` clauses
- No `except Exception` without logging
- Specific exceptions caught where possible
- Errors logged before re-raising
- No sensitive data in error messages
- Custom exceptions used where appropriate

## Category 4 — Documentation
- Module level docstring present
- All public functions have docstrings
- Docstrings follow Google or NumPy style
- Args, Returns, Raises documented
- Complex logic has inline comments
- No misleading or outdated comments

## Category 5 — Function Design
- Functions do one thing (single responsibility)
- Functions under 50 lines ideally
- No more than 4 parameters ideally
- No mutable default arguments (def f(x=[]) ← bad)
- No global state modification
- Pure functions where possible

## Category 6 — Security (Python specific)
- No hardcoded secrets or credentials
- No use of eval() or exec()
- No shell=True in subprocess calls
- No pickle for untrusted data
- SQL queries use parameterized statements
- No sensitive data in logs

## Category 7 — Performance
- No unnecessary database calls in loops (N+1 problem)
- Generators used for large datasets where appropriate
- No repeated expensive operations that could be cached
- List comprehensions preferred over map/filter

## Category 8 — Pythonic Code
- Context managers used for resources (with statement)
- f-strings used instead of % formatting or .format()
- Enumerate used instead of range(len())
- Any/All used instead of manual loops where appropriate
- Dataclasses or Pydantic instead of plain dicts for structured data

## Category 9 — Testing Considerations
- Functions are testable (dependencies injectable)
- No hidden side effects
- Pure functions separated from I/O operations
- Edge cases handled (empty lists, None values, etc.)

## Category 10 — Project Specific (SecureVault)
- Security rules from CLAUDE.md followed
- No sensitive values logged
- Encryption/decryption only in security layer
- Session key never written to disk
- Generic error messages returned to browser

---

## Output Format

Provide review in this format:

### Summary
[2-3 sentence overall assessment]

### Results by Category
[Category name]: [✅/⚠️/❌] [brief finding]

### Critical Issues (❌ FAIL)
[Detailed explanation of each failing item with fix]

### Warnings (⚠️ WARN)  
[Detailed explanation of each warning with suggestion]

### Positive Highlights
[What was done particularly well]

### Recommended Changes
[Prioritized list of changes — most important first]