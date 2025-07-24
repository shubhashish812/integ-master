import unittest
from unittest.mock import patch, MagicMock
from JiraOAuth3LO import JiraOAuth3LO

class TestJiraOAuth3LO(unittest.TestCase):
    def setUp(self):
        self.mock_redis = MagicMock()
        self.jira = JiraOAuth3LO("client_id", "client_secret", "redirect_uri", redis_client=self.mock_redis)

    @patch("JiraOAuth3LO.requests.post")
    def test_call_token_api(self, mock_post):
        mock_response = MagicMock()
        mock_response.json.return_value = {"access_token": "abc", "refresh_token": "def"}
        mock_response.raise_for_status = lambda: None
        mock_post.return_value = mock_response

        result = self.jira.call_token_api("dummy_code")
        self.assertEqual(result["access_token"], "abc")
        self.assertEqual(result["refresh_token"], "def")

    @patch("JiraOAuth3LO.requests.get")
    def test_get_accessible_resources(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = [{"id": "cloud123"}]
        mock_response.raise_for_status = lambda: None
        mock_get.return_value = mock_response

        resources = self.jira.get_accessible_resources("dummy_token")
        self.assertEqual(resources[0]["id"], "cloud123")
        self.assertEqual(self.jira.cloud_id, "cloud123")

    def test_cache_and_load_token(self):
        import json, time
        token = {"access_token": "abc", "refresh_token": "def", "expires_at": int(time.time()) + 3600}
        self.mock_redis.get.return_value = json.dumps(token)
        loaded = self.jira.load_token()
        self.assertEqual(loaded["access_token"], "abc")

    def test_cache_token_to_redis(self):
        token = {"access_token": "abc"}
        self.jira.cache_token_to_redis(token, 3600)
        self.mock_redis.set.assert_called()

if __name__ == "__main__":
    unittest.main()