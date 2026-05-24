"""
app/schemas/auth.py

Pydantic request schemas for the authentication flow.

Two schemas cover the full auth lifecycle:
  - SetupRequest  — first-time vault initialisation (password + confirmation).
  - LoginRequest  — subsequent logins (password only).

Neither schema is ever serialised back to the client, so there is no response
schema here. The master password must never appear in any response body.

SECURITY NOTE: Validation errors raised by these schemas (e.g. passwords do not
match, password too short) are safe to return to the client — they contain no
internal state. The raw password values themselves must never be logged or
included in error detail strings.
"""

from pydantic import BaseModel, field_validator, model_validator


class SetupRequest(BaseModel):
    """Validated request body for POST /setup (first-time vault creation).

    Fields:
        password:         The master password chosen by the user. Must be at
                          least 8 characters. This value is hashed with Argon2id
                          and never stored in plaintext.
        confirm_password: Must be identical to `password`. Checked by the
                          `passwords_must_match` validator and discarded after
                          validation — it is never forwarded to a service layer.

    Raises:
        ValueError: If `password` is shorter than 8 characters, or if
                    `password` and `confirm_password` do not match.
    """

    password: str
    confirm_password: str

    @field_validator("password")
    @classmethod
    def password_min_length(cls, value: str) -> str:
        """Enforce a minimum master password length of 8 characters."""
        if len(value) < 12:
            raise ValueError("Master password must be at least 12 characters.")
        return value

    @model_validator(mode="after")
    def passwords_must_match(self) -> "SetupRequest":
        """Reject the request if the two password fields differ."""
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self


class LoginRequest(BaseModel):
    """Validated request body for POST /login.

    Fields:
        password: The master password entered by the user. Forwarded to
                  auth_service.login() for Argon2 verification and key
                  derivation. Never logged or stored.
    """

    password: str


class MessageResponse(BaseModel):
    """Generic response schema for operations that return a status message.

    Used by routes that do not return a resource (e.g. logout, delete) to
    provide a consistent JSON envelope.

    Fields:
        message: Human-readable description of the outcome.
        success: Whether the operation succeeded. Defaults to True.
    """

    message: str
    success: bool = True
