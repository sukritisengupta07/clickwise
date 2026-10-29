"""
Tests for detector.py. Run them with:  python -m unittest discover -v

All URLs here are made-up test examples. Nothing is ever opened or requested.
(203.0.113.x is a range reserved for documentation, and example.com / example.test
are reserved names, so none of these point at real sites.)
"""

import unittest

from detector import analyze_url


def rule_ids(result):
    return {item["id"] for item in result["indicators"]}


class TestInvalidInput(unittest.TestCase):
    def test_empty_input(self):
        self.assertFalse(analyze_url("")["valid"])

    def test_spaces_only(self):
        self.assertFalse(analyze_url("     ")["valid"])

    def test_none_input_does_not_crash(self):
        self.assertFalse(analyze_url(None)["valid"])

    def test_invalid_url_text(self):
        self.assertFalse(analyze_url("not a url")["valid"])      # contains a space
        self.assertFalse(analyze_url("hello")["valid"])          # no dot, not a domain

    def test_non_web_schemes_rejected(self):
        self.assertFalse(analyze_url("javascript:alert(1)")["valid"])
        self.assertFalse(analyze_url("ftp://example.com/file")["valid"])

    def test_bad_port_rejected(self):
        self.assertFalse(analyze_url("http://example.com:99999/")["valid"])

    def test_oversized_input_rejected(self):
        self.assertFalse(analyze_url("http://example.com/" + "a" * 3000)["valid"])

    def test_fake_ip_not_accepted_as_domain(self):
        self.assertFalse(analyze_url("http://999.999.999.999/")["valid"])


class TestNormalLooking(unittest.TestCase):
    def test_normal_https_url_triggers_nothing(self):
        result = analyze_url("https://www.example.com/about")
        self.assertTrue(result["valid"])
        self.assertEqual(result["indicators"], [])
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["category"], "Low Risk")

    def test_missing_scheme_is_assumed_not_penalised(self):
        result = analyze_url("example.com")
        self.assertTrue(result["valid"])
        self.assertTrue(result["assumed_scheme"])
        self.assertNotIn("plain_http", rule_ids(result))

    def test_whole_word_matching_avoids_false_positive(self):
        # "accounting" contains "account" but is not the word "account"
        result = analyze_url("https://accounting.example.com/")
        self.assertNotIn("suspicious_words", rule_ids(result))

    def test_login_page_on_normal_site_stays_low(self):
        result = analyze_url("https://www.example.com/login")
        self.assertEqual(result["category"], "Low Risk")

    def test_https_does_not_lower_the_score(self):
        http = analyze_url("http://203.0.113.5/")["score"]
        https = analyze_url("https://203.0.113.5/")["score"]
        self.assertEqual(https, http - 5)        # only the small plain-http rule differs


class TestRules(unittest.TestCase):
    def test_ipv4_host(self):
        result = analyze_url("http://203.0.113.5/index.html")
        self.assertIn("ip_host", rule_ids(result))

    def test_ipv6_host(self):
        result = analyze_url("http://[2001:db8::1]/")
        self.assertTrue(result["valid"])
        self.assertIn("ip_host", rule_ids(result))

    def test_at_symbol_in_address(self):
        result = analyze_url("https://www.example.com@203.0.113.9/")
        self.assertIn("at_symbol", rule_ids(result))

    def test_at_symbol_in_path_is_not_flagged(self):
        result = analyze_url("https://www.example.com/user@name")
        self.assertNotIn("at_symbol", rule_ids(result))

    def test_long_url(self):
        result = analyze_url("https://www.example.com/" + "a" * 120)
        self.assertIn("long_url", rule_ids(result))

    def test_many_subdomains(self):
        result = analyze_url("https://a.b.c.d.example.com/")
        self.assertIn("many_subdomains", rule_ids(result))

    def test_www_is_not_counted_as_subdomain(self):
        result = analyze_url("https://www.shop.example.com/")
        self.assertNotIn("many_subdomains", rule_ids(result))

    def test_shortener(self):
        result = analyze_url("https://bit.ly/abc123")
        self.assertIn("url_shortener", rule_ids(result))

    def test_many_hyphens(self):
        result = analyze_url("https://my-super-secure-site.example.com/")
        self.assertIn("many_hyphens", rule_ids(result))

    def test_punycode_host(self):
        result = analyze_url("https://xn--80ak6aa92e.example.com/")
        self.assertIn("punycode", rule_ids(result))

    def test_unicode_host_is_flagged_not_crashing(self):
        result = analyze_url("https://m\u00fcnchen.example.com/")
        self.assertTrue(result["valid"])
        self.assertIn("punycode", rule_ids(result))

    def test_plain_http_only_when_typed(self):
        self.assertIn("plain_http", rule_ids(analyze_url("http://www.example.com/")))
        self.assertNotIn("plain_http", rule_ids(analyze_url("https://www.example.com/")))


class TestCombinations(unittest.TestCase):
    def test_suspicious_pattern_url(self):
        result = analyze_url("http://secure-login-verify-account.example.test/update")
        self.assertIn("suspicious_words", rule_ids(result))
        self.assertIn("many_hyphens", rule_ids(result))

    def test_multiple_rules_give_high_risk(self):
        result = analyze_url("http://paypal.secure-login-verify.example.test@203.0.113.9/login?verify=1")
        self.assertGreaterEqual(len(result["indicators"]), 3)
        self.assertEqual(result["category"], "High Risk")

    def test_related_rules_are_capped(self):
        # hyphens + words overlap, so together they may not exceed the group cap of 25
        result = analyze_url("https://secure-login-verify-account-update.example.com/password/confirm")
        wording = sum(i["points"] for i in result["indicators"] if i["id"] in ("suspicious_words", "many_hyphens"))
        self.assertLessEqual(wording, 25)

    def test_score_never_exceeds_100(self):
        url = "http://a.b.c.d.secure-login-verify-account-update.example.test@203.0.113.9/" + "x" * 250 + "/login"
        self.assertLessEqual(analyze_url(url)["score"], 100)

    def test_medium_example(self):
        result = analyze_url("http://203.0.113.5/secure/login")
        self.assertEqual(result["category"], "Medium Risk")


if __name__ == "__main__":
    unittest.main()
