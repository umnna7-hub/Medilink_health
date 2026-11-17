import os
import unittest
from unittest.mock import patch

import database


class DatabaseTlsConfigurationTests(unittest.TestCase):
    base_environment = {
        "DB_HOST": "127.0.0.1",
        "DB_PORT": "3306",
        "DB_USER": "test-user",
        "DB_PASSWORD": "test-password",
        "DB_NAME": "test-database",
    }

    def test_tls_is_not_enabled_by_default(self):
        with patch.dict(os.environ, self.base_environment, clear=True):
            with patch.object(database.mysql.connector, "connect") as connect:
                database.get_db_connection()

        connect.assert_called_once_with(
            host="127.0.0.1",
            port=3306,
            user="test-user",
            password="test-password",
            database="test-database",
        )

    def test_tls_enables_ssl_and_uses_optional_ca_file(self):
        environment = {
            **self.base_environment,
            "DB_SSL": "true",
            "DB_SSL_CA": r"C:\test-certs\ca.pem",
        }
        with patch.dict(os.environ, environment, clear=True):
            with patch.object(database.mysql.connector, "connect") as connect:
                database.get_db_connection()

        connect.assert_called_once_with(
            host="127.0.0.1",
            port=3306,
            user="test-user",
            password="test-password",
            database="test-database",
            ssl_disabled=False,
            ssl_ca=r"C:\test-certs\ca.pem",
        )

    def test_tls_can_be_enabled_without_a_ca_file(self):
        environment = {**self.base_environment, "DB_SSL": "TRUE"}
        with patch.dict(os.environ, environment, clear=True):
            with patch.object(database.mysql.connector, "connect") as connect:
                database.get_db_connection()

        self.assertIs(
            connect.call_args.kwargs["ssl_disabled"], False
        )
        self.assertNotIn("ssl_ca", connect.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
