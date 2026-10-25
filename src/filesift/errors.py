"""Exception hierarchy. Every class carries the process exit code it maps to (Spec §9.2)."""


class FileSiftError(Exception):
    """Base class for expected failures. Unclassified failures are operational (exit 4)."""

    exit_code = 4


class ConfigError(FileSiftError):
    """Invalid arguments or configuration."""

    exit_code = 2


class BaselineExistsError(FileSiftError):
    """``init-baseline`` would overwrite an existing baseline without ``--force``."""

    exit_code = 2


class BaselineError(FileSiftError):
    """The baseline is missing, corrupt, invalid, incompatible, or failed authentication."""

    exit_code = 3


class BaselineMissingError(BaselineError):
    """No baseline exists at the given path. A baseline is never auto-created by ``scan``."""


class BaselineCorruptError(BaselineError):
    """The baseline is not valid UTF-8 JSON."""


class BaselineInvalidError(BaselineError):
    """The baseline parsed but failed structural validation (schema, digests, paths, duplicate keys)."""


class BaselineAuthError(BaselineError):
    """HMAC verification failed, or the downgrade matrix refused the baseline."""


class RootUnreadableError(FileSiftError):
    """The target directory itself could not be listed; no comparison is possible."""

    exit_code = 4


class OperationalError(FileSiftError):
    """A write or other operational step failed."""

    exit_code = 4
