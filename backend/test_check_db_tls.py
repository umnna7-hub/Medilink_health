import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import Mock, patch

import check_db_tls


class CheckDatabaseTlsTests(unittest.TestCase):
    def check_cipher(self, cipher):
        cursor = Mock()
        cursor.fetchone.return_value = ("Ssl_cipher", cipher)
        connection = Mock()
        connection.cursor.return_value = cursor
        output = StringIO()

        with patch.object(
            check_db_tls, "get_db_connection", return_value=connection
        ):
            with redirect_stdout(output):
                result = check_db_tls.main()

        cursor.execute.assert_called_once_with(
            "SHOW STATUS LIKE 'Ssl_cipher'"
        )
        cursor.close.assert_called_once()
        connection.close.assert_called_once()
        return result, output.getvalue()

    def test_prints_cipher_and_succeeds_when_tls_is_active(self):
        result, output = self.check_cipher("TLS_AES_256_GCM_SHA384")

        self.assertEqual(result, 0)
        self.assertIn("TLS_AES_256_GCM_SHA384", output)

    def test_reports_inactive_tls_and_fails_when_cipher_is_empty(self):
        result, output = self.check_cipher("")

        self.assertEqual(result, 1)
        self.assertEqual(output.strip(), "TLS NOT ACTIVE")

    def test_reports_inactive_tls_when_status_row_is_missing(self):
        cursor = Mock()
        cursor.fetchone.return_value = None
        connection = Mock()
        connection.cursor.return_value = cursor
        output = StringIO()

        with patch.object(
            check_db_tls, "get_db_connection", return_value=connection
        ):
            with redirect_stdout(output):
                result = check_db_tls.main()

        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue().strip(), "TLS NOT ACTIVE")


if __name__ == "__main__":
    unittest.main()
