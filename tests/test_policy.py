import unittest
from privalyse_scanner.models.config import PolicyConfig

class TestPolicyConfig(unittest.TestCase):
    def test_blocked_countries(self):
        policy = PolicyConfig(blocked_countries=["US", "CN"])
        self.assertFalse(policy.is_country_allowed("US"))
        self.assertFalse(policy.is_country_allowed("CN"))
        self.assertTrue(policy.is_country_allowed("DE"))
        self.assertTrue(policy.is_country_allowed("EU"))

    def test_allowed_countries(self):
        policy = PolicyConfig(allowed_countries=["EU", "DE"])
        self.assertTrue(policy.is_country_allowed("EU"))
        self.assertTrue(policy.is_country_allowed("DE"))
        self.assertFalse(policy.is_country_allowed("US"))
        self.assertFalse(policy.is_country_allowed("CN"))

    def test_blocked_providers(self):
        policy = PolicyConfig(blocked_providers=["OpenAI", "Google"])
        self.assertFalse(policy.is_provider_allowed("OpenAI"))
        self.assertFalse(policy.is_provider_allowed("Google Analytics"))
        self.assertTrue(policy.is_provider_allowed("Sentry"))

if __name__ == '__main__':
    unittest.main()
