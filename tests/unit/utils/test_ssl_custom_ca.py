"""Tests for custom CA bundle SSL functionality."""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from requests.sessions import Session

from mcp_atlassian.utils.env import parse_ssl_verify, validate_ca_bundle_path
from mcp_atlassian.utils.ssl import SSLIgnoreAdapter, configure_ssl_verification


class TestParseSslVerify:
    """Test the parse_ssl_verify function."""

    def test_boolean_true_standard_values(self, monkeypatch):
        """Test parse_ssl_verify with standard boolean true values."""
        true_values = ["true", "1", "yes"]

        for value in true_values:
            monkeypatch.setenv("SSL_VERIFY", value)
            result = parse_ssl_verify("SSL_VERIFY")
            assert result is True
            assert isinstance(result, bool)

        # Test uppercase variants
        for value in true_values:
            monkeypatch.setenv("SSL_VERIFY", value.upper())
            result = parse_ssl_verify("SSL_VERIFY")
            assert result is True
            assert isinstance(result, bool)

        # Test mixed case variants
        for value in true_values:
            monkeypatch.setenv("SSL_VERIFY", value.capitalize())
            result = parse_ssl_verify("SSL_VERIFY")
            assert result is True
            assert isinstance(result, bool)

    def test_boolean_false_standard_values(self, monkeypatch):
        """Test parse_ssl_verify with standard boolean false values."""
        false_values = ["false", "0", "no"]

        for value in false_values:
            monkeypatch.setenv("SSL_VERIFY", value)
            result = parse_ssl_verify("SSL_VERIFY")
            assert result is False
            assert isinstance(result, bool)

        # Test uppercase variants
        for value in false_values:
            monkeypatch.setenv("SSL_VERIFY", value.upper())
            result = parse_ssl_verify("SSL_VERIFY")
            assert result is False
            assert isinstance(result, bool)

        # Test mixed case variants
        for value in false_values:
            monkeypatch.setenv("SSL_VERIFY", value.capitalize())
            result = parse_ssl_verify("SSL_VERIFY")
            assert result is False
            assert isinstance(result, bool)

    def test_valid_ca_bundle_path(self, monkeypatch):
        """Test parse_ssl_verify with valid CA bundle file path."""
        # Create a temporary CA bundle file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".crt", delete=False
        ) as temp_file:
            temp_file.write("-----BEGIN CERTIFICATE-----\n")
            temp_file.write("MIIDXTCCAkWgAwIBAgIJAKL0UG\n")
            temp_file.write("-----END CERTIFICATE-----\n")
            temp_path = temp_file.name

        try:
            monkeypatch.setenv("SSL_VERIFY", temp_path)
            result = parse_ssl_verify("SSL_VERIFY")
            assert result == temp_path
            assert isinstance(result, str)
        finally:
            # Clean up temporary file
            Path(temp_path).unlink(missing_ok=True)

    def test_invalid_ca_bundle_path_fallback_to_true(self, monkeypatch):
        """Test parse_ssl_verify with invalid path falls back to True with warning."""
        invalid_path = "/nonexistent/path/to/ca-bundle.crt"
        monkeypatch.setenv("SSL_VERIFY", invalid_path)

        with patch("mcp_atlassian.utils.env.logger") as mock_logger:
            result = parse_ssl_verify("SSL_VERIFY")
            assert result is True
            assert isinstance(result, bool)

            # Verify warning was logged
            mock_logger.warning.assert_called_once()
            warning_message = mock_logger.warning.call_args[0][0]
            assert "SSL_VERIFY" in warning_message
            assert invalid_path in warning_message
            assert "non-existent" in warning_message.lower()
            assert "ssl_verify=True" in warning_message

    def test_default_value_when_unset(self, monkeypatch):
        """Test parse_ssl_verify with unset environment variable uses default."""
        monkeypatch.delenv("SSL_VERIFY", raising=False)

        # Default is "true"
        result = parse_ssl_verify("SSL_VERIFY")
        assert result is True

    def test_custom_default_value(self, monkeypatch):
        """Test parse_ssl_verify with custom default value."""
        monkeypatch.delenv("SSL_VERIFY", raising=False)

        # Custom default "false"
        result = parse_ssl_verify("SSL_VERIFY", default="false")
        assert result is False

        # Custom default "1"
        result = parse_ssl_verify("SSL_VERIFY", default="1")
        assert result is True

    def test_whitespace_handling(self, monkeypatch):
        """Test parse_ssl_verify strips whitespace from values."""
        # Leading/trailing whitespace should be stripped
        monkeypatch.setenv("SSL_VERIFY", "  true  ")
        result = parse_ssl_verify("SSL_VERIFY")
        assert result is True

        monkeypatch.setenv("SSL_VERIFY", "\tfalse\n")
        result = parse_ssl_verify("SSL_VERIFY")
        assert result is False

        # Test with file path with whitespace
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".crt", delete=False
        ) as temp_file:
            temp_file.write("-----BEGIN CERTIFICATE-----\n")
            temp_path = temp_file.name

        try:
            monkeypatch.setenv("SSL_VERIFY", f"  {temp_path}  ")
            result = parse_ssl_verify("SSL_VERIFY")
            assert result == temp_path
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_ca_bundle_path_with_info_log(self, monkeypatch):
        """Test parse_ssl_verify logs info message when using custom CA bundle."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".crt", delete=False
        ) as temp_file:
            temp_file.write("-----BEGIN CERTIFICATE-----\n")
            temp_path = temp_file.name

        try:
            monkeypatch.setenv("SSL_VERIFY", temp_path)

            with patch("mcp_atlassian.utils.env.logger") as mock_logger:
                result = parse_ssl_verify("SSL_VERIFY")
                assert result == temp_path

                # Verify info was logged
                mock_logger.info.assert_called_once()
                info_message = mock_logger.info.call_args[0][0]
                assert "SSL_VERIFY" in info_message
                assert "custom CA bundle" in info_message.lower()
                assert temp_path in info_message
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_relative_path_that_exists(self, monkeypatch, tmp_path):
        """Test parse_ssl_verify with relative path that exists."""
        # Create a temporary file in current directory context
        ca_file = tmp_path / "ca-bundle.crt"
        ca_file.write_text("-----BEGIN CERTIFICATE-----\n")

        # Change to the temporary directory and use relative path
        import os

        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            monkeypatch.setenv("SSL_VERIFY", "ca-bundle.crt")
            result = parse_ssl_verify("SSL_VERIFY")
            # Should return the relative path as-is since os.path.isfile checks it
            assert result == "ca-bundle.crt"
        finally:
            os.chdir(original_cwd)


class TestValidateCaBundlePath:
    """Test the validate_ca_bundle_path function."""

    def test_valid_ca_bundle_file(self):
        """Test validate_ca_bundle_path with existing readable file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".crt", delete=False
        ) as temp_file:
            temp_file.write("-----BEGIN CERTIFICATE-----\n")
            temp_path = temp_file.name

        try:
            with patch("mcp_atlassian.utils.env.logger") as mock_logger:
                result = validate_ca_bundle_path(temp_path)
                assert result is True

                # Verify debug log was called
                mock_logger.debug.assert_called_once()
                debug_message = mock_logger.debug.call_args[0][0]
                assert "CA bundle validated" in debug_message
                assert temp_path in debug_message
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_nonexistent_ca_bundle_file(self):
        """Test validate_ca_bundle_path with non-existent file."""
        nonexistent_path = "/nonexistent/path/to/ca-bundle.crt"

        with patch("mcp_atlassian.utils.env.logger") as mock_logger:
            result = validate_ca_bundle_path(nonexistent_path)
            assert result is False

            # Verify error log was called
            mock_logger.error.assert_called_once()
            error_message = mock_logger.error.call_args[0][0]
            assert "CA bundle file not found" in error_message
            assert nonexistent_path in error_message

    def test_unreadable_ca_bundle_file(self):
        """Test validate_ca_bundle_path with file without read permissions."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".crt", delete=False
        ) as temp_file:
            temp_file.write("-----BEGIN CERTIFICATE-----\n")
            temp_path = temp_file.name

        try:
            # Remove read permissions
            import os
            import stat

            os.chmod(temp_path, stat.S_IWUSR)  # Write-only permission

            # Mock os.access to simulate unreadable file
            with patch("os.access", return_value=False):
                with patch("os.path.isfile", return_value=True):
                    with patch("mcp_atlassian.utils.env.logger") as mock_logger:
                        result = validate_ca_bundle_path(temp_path)
                        assert result is False

                        # Verify error log was called
                        mock_logger.error.assert_called_once()
                        error_message = mock_logger.error.call_args[0][0]
                        assert "CA bundle file not readable" in error_message
                        assert temp_path in error_message
        finally:
            # Restore permissions and clean up
            import os
            import stat

            os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
            Path(temp_path).unlink(missing_ok=True)

    def test_directory_instead_of_file(self):
        """Test validate_ca_bundle_path with directory path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("mcp_atlassian.utils.env.logger") as mock_logger:
                result = validate_ca_bundle_path(temp_dir)
                assert result is False

                # Verify error log was called (directory is not a file)
                mock_logger.error.assert_called_once()
                error_message = mock_logger.error.call_args[0][0]
                assert "CA bundle file not found" in error_message


class TestConfigureSslVerificationCustomCa:
    """Test the configure_ssl_verification function with custom CA bundle."""

    def test_ssl_verify_true(self):
        """Test configure_ssl_verification with ssl_verify=True (default behavior)."""
        service_name = "TestService"
        url = "https://test.example.com/api"
        session = MagicMock(spec=Session)
        ssl_verify = True

        with patch("mcp_atlassian.utils.ssl.logger") as mock_logger:
            configure_ssl_verification(service_name, url, session, ssl_verify)

            # Should not mount any adapters
            session.mount.assert_not_called()

            # Should log debug message
            mock_logger.debug.assert_called_once()
            debug_message = mock_logger.debug.call_args[0][0]
            assert "TestService" in debug_message
            assert "SSL verification enabled" in debug_message
            assert "system CA bundle" in debug_message

    def test_ssl_verify_false(self):
        """Test configure_ssl_verification with ssl_verify=False (disable SSL)."""
        service_name = "TestService"
        url = "https://test.example.com/api"
        session = MagicMock(spec=Session)
        ssl_verify = False

        with patch("mcp_atlassian.utils.ssl.logger") as mock_logger:
            with patch(
                "mcp_atlassian.utils.ssl.SSLIgnoreAdapter"
            ) as mock_adapter_class:
                mock_adapter = MagicMock()
                mock_adapter_class.return_value = mock_adapter

                configure_ssl_verification(service_name, url, session, ssl_verify)

                # Should create SSLIgnoreAdapter
                mock_adapter_class.assert_called_once()

                # Should mount adapter for both https and http
                assert session.mount.call_count == 2
                session.mount.assert_any_call("https://test.example.com", mock_adapter)
                session.mount.assert_any_call("http://test.example.com", mock_adapter)

                # Should log warning
                mock_logger.warning.assert_called_once()
                warning_message = mock_logger.warning.call_args[0][0]
                assert "TestService" in warning_message
                assert "SSL verification disabled" in warning_message
                assert "insecure" in warning_message.lower()

    def test_ssl_verify_custom_ca_bundle_path(self):
        """Test configure_ssl_verification with custom CA bundle path."""
        service_name = "TestService"
        url = "https://test.example.com/api"
        session = MagicMock(spec=Session)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".crt", delete=False
        ) as temp_file:
            temp_file.write("-----BEGIN CERTIFICATE-----\n")
            ca_bundle_path = temp_file.name

        try:
            with patch("mcp_atlassian.utils.ssl.logger") as mock_logger:
                configure_ssl_verification(
                    service_name, url, session, ssl_verify=ca_bundle_path
                )

                # Should not mount any adapters
                session.mount.assert_not_called()

                # Should set session.verify to the CA bundle path
                assert session.verify == ca_bundle_path

                # Should log info message
                mock_logger.info.assert_called_once()
                info_message = mock_logger.info.call_args[0][0]
                assert "TestService" in info_message
                assert "custom CA bundle" in info_message.lower()
                assert ca_bundle_path[:50] in info_message
        finally:
            Path(ca_bundle_path).unlink(missing_ok=True)

    def test_ssl_verify_long_ca_bundle_path_truncated(self):
        """Test configure_ssl_verification truncates long CA bundle paths in logs."""
        service_name = "TestService"
        url = "https://test.example.com/api"
        session = MagicMock(spec=Session)

        # Create a very long path
        long_path = "/very/long/path/" + "a" * 100 + "/ca-bundle.crt"

        with patch("mcp_atlassian.utils.ssl.logger") as mock_logger:
            configure_ssl_verification(service_name, url, session, ssl_verify=long_path)

            # Should log info message with truncated path
            mock_logger.info.assert_called_once()
            info_message = mock_logger.info.call_args[0][0]
            assert "..." in info_message  # Path should be truncated
            assert long_path[:50] in info_message

    def test_ssl_verify_with_real_session_true(self):
        """Test SSL verification configuration with real Session and ssl_verify=True."""
        session = Session()
        original_verify = session.verify
        original_adapters_count = len(session.adapters)

        with patch("mcp_atlassian.utils.ssl.logger"):
            configure_ssl_verification(
                service_name="Test",
                url="https://example.com",
                session=session,
                ssl_verify=True,
            )

        # session.verify should remain unchanged
        assert session.verify == original_verify
        # No new adapters should be added
        assert len(session.adapters) == original_adapters_count

    def test_ssl_verify_with_real_session_custom_ca(self):
        """Test SSL verification configuration with real Session and custom CA."""
        session = Session()
        original_adapters_count = len(session.adapters)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".crt", delete=False
        ) as temp_file:
            temp_file.write("-----BEGIN CERTIFICATE-----\n")
            ca_bundle_path = temp_file.name

        try:
            with patch("mcp_atlassian.utils.ssl.logger"):
                configure_ssl_verification(
                    service_name="Test",
                    url="https://example.com",
                    session=session,
                    ssl_verify=ca_bundle_path,
                )

            # session.verify should be set to CA bundle path
            assert session.verify == ca_bundle_path
            # No new adapters should be added
            assert len(session.adapters) == original_adapters_count
        finally:
            Path(ca_bundle_path).unlink(missing_ok=True)

    def test_ssl_verify_with_url_with_port(self):
        """Test configure_ssl_verification extracts domain correctly with port."""
        service_name = "TestService"
        url = "https://test.example.com:8443/api"
        session = MagicMock(spec=Session)
        ssl_verify = False

        with patch("mcp_atlassian.utils.ssl.logger"):
            with patch(
                "mcp_atlassian.utils.ssl.SSLIgnoreAdapter"
            ) as mock_adapter_class:
                mock_adapter = MagicMock()
                mock_adapter_class.return_value = mock_adapter

                configure_ssl_verification(service_name, url, session, ssl_verify)

                # Should mount adapter with domain including port
                session.mount.assert_any_call(
                    "https://test.example.com:8443", mock_adapter
                )
                session.mount.assert_any_call(
                    "http://test.example.com:8443", mock_adapter
                )

    def test_ssl_verify_with_url_with_path(self):
        """Test configure_ssl_verification extracts domain correctly ignoring path."""
        service_name = "TestService"
        url = "https://test.example.com/very/long/path/to/api"
        session = MagicMock(spec=Session)
        ssl_verify = False

        with patch("mcp_atlassian.utils.ssl.logger"):
            with patch(
                "mcp_atlassian.utils.ssl.SSLIgnoreAdapter"
            ) as mock_adapter_class:
                mock_adapter = MagicMock()
                mock_adapter_class.return_value = mock_adapter

                configure_ssl_verification(service_name, url, session, ssl_verify)

                # Should mount adapter with domain only (no path)
                session.mount.assert_any_call("https://test.example.com", mock_adapter)
                session.mount.assert_any_call("http://test.example.com", mock_adapter)


class TestEdgeCasesCustomCa:
    """Test edge cases for custom CA functionality."""

    def test_parse_ssl_verify_empty_string(self, monkeypatch):
        """Test parse_ssl_verify with empty string value."""
        monkeypatch.setenv("SSL_VERIFY", "")

        with patch("mcp_atlassian.utils.env.logger") as mock_logger:
            result = parse_ssl_verify("SSL_VERIFY")
            # Empty string after strip should fall back to True
            assert result is True
            # Should log warning about non-existent file
            mock_logger.warning.assert_called_once()

    def test_configure_ssl_verification_none_value(self):
        """Test configure_ssl_verification handles None gracefully."""
        service_name = "TestService"
        url = "https://test.example.com/api"
        session = MagicMock(spec=Session)

        # None should be treated similar to False (though parse_ssl_verify won't return None)
        with patch("mcp_atlassian.utils.ssl.logger"):
            # This should not raise an exception
            configure_ssl_verification(service_name, url, session, ssl_verify=None)
            # None is falsy, but not explicitly False, so no adapter should be mounted
            session.mount.assert_not_called()

    def test_validate_ca_bundle_path_empty_string(self):
        """Test validate_ca_bundle_path with empty string."""
        with patch("mcp_atlassian.utils.env.logger") as mock_logger:
            result = validate_ca_bundle_path("")
            assert result is False
            mock_logger.error.assert_called_once()

    def test_parse_ssl_verify_special_characters_in_path(self, monkeypatch):
        """Test parse_ssl_verify with special characters in file path."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".crt", prefix="ca-bundle@#$", delete=False
        ) as temp_file:
            temp_file.write("-----BEGIN CERTIFICATE-----\n")
            temp_path = temp_file.name

        try:
            monkeypatch.setenv("SSL_VERIFY", temp_path)
            result = parse_ssl_verify("SSL_VERIFY")
            assert result == temp_path
        finally:
            Path(temp_path).unlink(missing_ok=True)
