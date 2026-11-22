"""Typed errors with stable field paths."""


class MirrorPlanError(Exception):
    """Base error."""


class ValidationError(MirrorPlanError):
    """The input document is structurally invalid (exit code 2).

    ``field`` is a deterministic JSON-style path such as ``taps[0].id``.
    """

    def __init__(self, field, message):
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}" if field else message)


class AuditFailure(MirrorPlanError):
    """A structurally valid plan fails recomputed audit rules (exit code 3)."""

    def __init__(self, reason, detail):
        self.reason = reason
        self.detail = detail
        super().__init__(f"audit failed: {reason}")


class StoreError(MirrorPlanError):
    """Record/history conflict or missing version (exit code 3)."""

    def __init__(self, message, code="conflict"):
        self.message = message
        self.code = code
        super().__init__(message)
