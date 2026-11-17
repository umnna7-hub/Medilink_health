import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

import rate_limiter


class RateLimiterTests(unittest.TestCase):
    def setUp(self):
        rate_limiter.request_history.clear()
        self.client = rate_limiter.app.test_client()

    def test_rapid_requests_are_flagged_and_excess_request_is_limited(self):
        output = StringIO()
        with patch.object(rate_limiter.time, "time", return_value=1000.0):
            with redirect_stdout(output):
                responses = [self.client.get("/demo") for _ in range(6)]

        self.assertEqual(
            [response.status_code for response in responses],
            [200, 200, 200, 200, 200, 429],
        )
        self.assertIn("ANOMALY DETECTED", output.getvalue())
        self.assertIn("RATE LIMIT EXCEEDED", output.getvalue())


if __name__ == "__main__":
    unittest.main()
