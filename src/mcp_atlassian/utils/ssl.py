"""SSL-related utility functions for MCP Atlassian."""

import logging
import ssl
from typing import Any
from urllib.parse import urlparse

from requests.adapters import HTTPAdapter
from requests.sessions import Session
from urllib3.poolmanager import PoolManager

logger = logging.getLogger("mcp-atlassian")


class SSLIgnoreAdapter(HTTPAdapter):
    """HTTP adapter that ignores SSL verification.

    A custom transport adapter that disables SSL certificate verification for specific domains.
    This implementation ensures that both verify_mode is set to CERT_NONE and check_hostname
    is disabled, which is required for properly ignoring SSL certificates.

    This adapter also enables legacy SSL renegotiation which may be required for some older servers.
    Note that this reduces security and should only be used when absolutely necessary.
    """

    def init_poolmanager(
        self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any
    ) -> None:
        """Initialize the connection pool manager with SSL verification disabled.

        This method is called when the adapter is created, and it's the proper place to
        disable SSL verification completely.

        Args:
            connections: Number of connections to save in the pool
            maxsize: Maximum number of connections in the pool
            block: Whether to block when the pool is full
            pool_kwargs: Additional arguments for the pool manager
        """
        # Configure SSL context to disable verification completely
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Enable legacy SSL renegotiation
        context.options |= 0x4  # SSL_OP_LEGACY_SERVER_CONNECT
        context.options |= 0x40000  # SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION

        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=context,
            **pool_kwargs,
        )

    def cert_verify(self, conn: Any, url: str, verify: bool, cert: Any | None) -> None:
        """Override cert verification to disable SSL verification.

        This method is still included for backward compatibility, but the main
        SSL disabling happens in init_poolmanager.

        Args:
            conn: The connection
            url: The URL being requested
            verify: The original verify parameter (ignored)
            cert: Client certificate path
        """
        super().cert_verify(conn, url, verify=False, cert=cert)


def configure_ssl_verification(
    service_name: str, url: str, session: Session, ssl_verify: bool | str
) -> None:
    """Configure SSL verification for a specific service.

    This function supports three modes of SSL verification:
    1. True: Use system CA bundle for verification (default, secure)
    2. False: Disable SSL verification completely (insecure, testing only)
    3. str: Path to custom CA bundle file (secure, for custom CAs)

    Args:
        service_name: Name of the service for logging (e.g., "Confluence", "Jira")
        url: The base URL of the service
        session: The requests session to configure
        ssl_verify: SSL verification setting:
            - True: verify with system CA bundle
            - False: disable verification (insecure)
            - str: path to custom CA bundle file
    """
    if ssl_verify is False:  # Explicitly check for False
        logger.warning(
            f"{service_name} SSL verification disabled. "
            f"This is insecure and should only be used in testing environments."
        )

        # Get the domain from the configured URL
        domain = urlparse(url).netloc

        # Mount the adapter to handle requests to this domain
        adapter = SSLIgnoreAdapter()
        session.mount(f"https://{domain}", adapter)
        session.mount(f"http://{domain}", adapter)

    elif isinstance(ssl_verify, str):
        # Custom CA bundle path
        logger.info(
            f"{service_name} using custom CA bundle: {ssl_verify[:50]}{'...' if len(ssl_verify) > 50 else ''}"
        )
        # Set session.verify to the custom CA path
        # This tells requests library to use this specific CA bundle
        session.verify = ssl_verify

    else:  # ssl_verify is True
        # Default behavior - use system CA bundle
        # session.verify remains True (default)
        logger.debug(f"{service_name} SSL verification enabled with system CA bundle")
