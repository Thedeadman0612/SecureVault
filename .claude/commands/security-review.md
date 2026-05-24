---
description: Review a security module for vulnerabilities. Usage: /security-review <path-to-file> (e.g. /security-review app/security/encryption.py)
---

Review the security module at $ARGUMENTS for these issues:

1. Are any passwords, keys, or decrypted values logged?
2. Are exceptions handled without exposing internals?
3. Is os.urandom used for salt generation?
4. Are PBKDF2HMAC instances created fresh each call?
5. Is the derived key ever written to disk?
6. Are error messages generic (no internal details)?
7. Does it follow all rules in CLAUDE.md security section?

Report each check as PASS or FAIL with explanation.