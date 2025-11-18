import unittest
from unittest.mock import MagicMock, patch
from src.redteam.scanners.api_scanner import APISecurityTester

class TestAPISecurityTester(unittest.TestCase):
    def setUp(self):
        self.config = {
            'api_url': 'http://test.com',
            'auth_token': 'test_token',
            'swagger_file': 'swagger.json',
            'rate_limit': 10,
        }

    @patch('src.redteam.scanners.api_scanner.RateLimiter')
    @patch('src.redteam.scanners.api_scanner.requests.Session')
    def test_init(self, mock_session, mock_rate_limiter):
        """Tests that the scanner can be initialized correctly."""
        scanner = APISecurityTester(self.config)
        self.assertEqual(scanner.base_url, 'http://test.com')
        self.assertEqual(scanner.auth_token, 'test_token')
        mock_rate_limiter.assert_called_once_with(max_requests=10, time_window=1)

if __name__ == '__main__':
    unittest.main()
