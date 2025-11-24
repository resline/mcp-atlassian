"""Environment variable utility functions for MCP Atlassian."""

import logging
import os

logger = logging.getLogger(__name__)


def is_env_truthy(env_var_name: str, default: str = "") -> bool:
    """Check if environment variable is set to a standard truthy value.

    Considers 'true', '1', 'yes' as truthy values (case-insensitive).
    Used for most MCP environment variables.

    Args:
        env_var_name: Name of the environment variable to check
        default: Default value if environment variable is not set

    Returns:
        True if the environment variable is set to a truthy value, False otherwise
    """
    return os.getenv(env_var_name, default).lower() in ("true", "1", "yes")


def is_env_extended_truthy(env_var_name: str, default: str = "") -> bool:
    """Check if environment variable is set to an extended truthy value.

    Considers 'true', '1', 'yes', 'y', 'on' as truthy values (case-insensitive).
    Used for READ_ONLY_MODE and similar flags.

    Args:
        env_var_name: Name of the environment variable to check
        default: Default value if environment variable is not set

    Returns:
        True if the environment variable is set to a truthy value, False otherwise
    """
    return os.getenv(env_var_name, default).lower() in ("true", "1", "yes", "y", "on")


def parse_ssl_verify(env_var_name: str, default: str = "true") -> bool | str:
    """Parse SSL verification setting - supports bool and custom CA path.

    Args:
        env_var_name: Name of the environment variable
        default: Default value if not set (defaults to "true")

    Returns:
        - True: Enable SSL verification with system CA bundle
        - False: Disable SSL verification (insecure)
        - str: Path to custom CA bundle file

    Examples:
        >>> # With JIRA_SSL_VERIFY=true
        >>> parse_ssl_verify("JIRA_SSL_VERIFY")
        True
        >>> # With JIRA_SSL_VERIFY=false
        >>> parse_ssl_verify("JIRA_SSL_VERIFY")
        False
        >>> # With JIRA_SSL_VERIFY=/path/to/ca.crt
        >>> parse_ssl_verify("JIRA_SSL_VERIFY")
        "/path/to/ca.crt"
    """
    value = os.getenv(env_var_name, default).strip()

    # Check for boolean false values
    if value.lower() in ("false", "0", "no"):
        return False

    # Check for boolean true values
    if value.lower() in ("true", "1", "yes"):
        return True

    # Treat as file path - validate it exists
    if os.path.isfile(value):
        logger.info(f"{env_var_name}: Using custom CA bundle at {value}")
        return value

    # Path doesn't exist - log warning and default to True
    logger.warning(
        f"{env_var_name}={value} points to non-existent file. "
        f"Defaulting to ssl_verify=True for secure verification."
    )
    return True


def is_env_ssl_verify(env_var_name: str, default: str = "true") -> bool:
    """Check SSL verification setting with secure defaults.

    Defaults to true unless explicitly set to false values.
    Used for SSL_VERIFY environment variables.

    Note: This function now uses parse_ssl_verify internally and always returns bool.
    For custom CA bundle support, use parse_ssl_verify directly.

    Args:
        env_var_name: Name of the environment variable to check
        default: Default value if environment variable is not set

    Returns:
        True unless explicitly set to false values
    """
    result = parse_ssl_verify(env_var_name, default)
    # If result is a string (CA path), treat as True for backward compatibility
    return result if isinstance(result, bool) else True


def get_custom_headers(env_var_name: str) -> dict[str, str]:
    """Parse custom headers from environment variable containing comma-separated key=value pairs.

    Args:
        env_var_name: Name of the environment variable to read

    Returns:
        Dictionary of parsed headers

    Examples:
        >>> # With CUSTOM_HEADERS="X-Custom=value1,X-Other=value2"
        >>> parse_custom_headers("CUSTOM_HEADERS")
        {'X-Custom': 'value1', 'X-Other': 'value2'}
        >>> # With unset environment variable
        >>> parse_custom_headers("UNSET_VAR")
        {}
    """
    header_string = os.getenv(env_var_name)
    if not header_string or not header_string.strip():
        return {}

    headers = {}
    pairs = header_string.split(",")

    for pair in pairs:
        pair = pair.strip()
        if not pair:
            continue

        if "=" not in pair:
            continue

        key, value = pair.split("=", 1)  # Split on first = only
        key = key.strip()
        value = value.strip()

        if key:  # Only add if key is not empty
            headers[key] = value

    return headers


def validate_ca_bundle_path(path: str) -> bool:
    """Validate that CA bundle file exists and is readable.

    Args:
        path: Path to CA bundle file

    Returns:
        True if file exists and is readable, False otherwise
    """
    if not os.path.isfile(path):
        logger.error(f"CA bundle file not found: {path}")
        return False

    if not os.access(path, os.R_OK):
        logger.error(f"CA bundle file not readable: {path}")
        return False

    logger.debug(f"CA bundle validated: {path}")
    return True
