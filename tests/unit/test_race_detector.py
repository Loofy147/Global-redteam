import unittest
from src.redteam.scanners.race_detector import RaceConditionDetector

class TestRaceConditionDetector(unittest.TestCase):
    def setUp(self):
        self.config = {
            'threads': 10,
            'iterations': 2,
            'api_url': 'http://test.com',
            'auth_token': 'test_token',
        }

    def test_init(self):
        """Tests that the scanner can be initialized correctly."""
        scanner = RaceConditionDetector(self.config)
        self.assertEqual(scanner.threads, 10)
        self.assertEqual(scanner.iterations, 2)

if __name__ == '__main__':
    unittest.main()
