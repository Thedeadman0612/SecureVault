---
description: Review a Jinja2 template for security issues. Usage: /template-review <path>
---

Review the template at $ARGUMENTS for these issues:

1. Are sensitive values escaped with tojson or | e filter?
2. Do external links use rel="noopener noreferrer"?
3. Are POST forms used for destructive actions (delete, logout)?
4. Are passwords/sensitive data embedded in page HTML?
5. Do forms have correct action URLs?
6. Is autocomplete="off" on sensitive fields?
7. Are error messages displayed without exposing internals?

Report each check as PASS or FAIL with explanation.