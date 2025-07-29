import unittest
from unittest.mock import patch, MagicMock
from JiraOAuth3LO import JiraOAuth3LO, JiraAuthBase

class TestJiraOAuth3LO(unittest.TestCase):
    def setUp(self):
        self.mock_redis = MagicMock()
        self.jira = JiraOAuth3LO("client_id", "client_secret", "redirect_uri", redis_client=self.mock_redis)

    def test_authbase_get_token(self):
        # Test JiraAuthBase authentication logic
        auth = JiraAuthBase("client_id", "client_secret", "redirect_uri", redis_client=self.mock_redis)
        with patch.object(auth, 'load_token', return_value={"access_token": "abc"}):
            token = auth.get_token()
            self.assertEqual(token, "abc")

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

    @patch("JiraOAuth3LO.requests.post")
    @patch.object(JiraOAuth3LO, 'get_accessible_resources')
    @patch.object(JiraOAuth3LO, 'get_token')
    def test_create_ticket(self, mock_get_token, mock_get_accessible_resources, mock_post):
        mock_get_token.return_value = "dummy_token"
        self.jira.cloud_id = "cloud123"
        mock_post.return_value = MagicMock(status_code=201, json=lambda: {"key": "PROJ-1"}, raise_for_status=lambda: None)
        data = {
            "fields": {
                "project": {"key": "PROJ"},
                "summary": "Test issue",
                "description": "Test desc",
                "issuetype": {"name": "Task"}
            }
        }
        result = self.jira.create_ticket(data)
        self.assertEqual(result["key"], "PROJ-1")

    @patch("JiraOAuth3LO.requests.put")
    @patch.object(JiraOAuth3LO, 'get_accessible_resources')
    @patch.object(JiraOAuth3LO, 'get_token')
    def test_update_ticket(self, mock_get_token, mock_get_accessible_resources, mock_put):
        mock_get_token.return_value = "dummy_token"
        self.jira.cloud_id = "cloud123"
        mock_put.return_value = MagicMock(status_code=204, raise_for_status=lambda: None)
        data = {"fields": {"summary": "Updated"}}
        result = self.jira.update_ticket("PROJ-1", data)
        self.assertTrue(result)

    @patch("JiraOAuth3LO.requests.delete")
    @patch.object(JiraOAuth3LO, 'get_accessible_resources')
    @patch.object(JiraOAuth3LO, 'get_token')
    def test_delete_ticket(self, mock_get_token, mock_get_accessible_resources, mock_delete):
        mock_get_token.return_value = "dummy_token"
        self.jira.cloud_id = "cloud123"
        mock_delete.return_value = MagicMock(status_code=204, raise_for_status=lambda: None)
        result = self.jira.delete_ticket("PROJ-1")
        self.assertTrue(result)

    @patch("JiraOAuth3LO.requests.get")
    @patch.object(JiraOAuth3LO, 'get_accessible_resources')
    @patch.object(JiraOAuth3LO, 'get_token')
    def test_get_ticket(self, mock_get_token, mock_get_accessible_resources, mock_get):
        mock_get_token.return_value = "dummy_token"
        self.jira.cloud_id = "cloud123"
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"key": "PROJ-1"}, raise_for_status=lambda: None)
        result = self.jira.get_ticket("PROJ-1")
        self.assertEqual(result["key"], "PROJ-1")

    @patch("JiraOAuth3LO.requests.get")
    @patch.object(JiraOAuth3LO, 'get_accessible_resources')
    @patch.object(JiraOAuth3LO, 'get_token')
    def test_list_tickets(self, mock_get_token, mock_get_accessible_resources, mock_get):
        mock_get_token.return_value = "dummy_token"
        self.jira.cloud_id = "cloud123"
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"issues": [{"key": "PROJ-1"}, {"key": "PROJ-2"}]}, raise_for_status=lambda: None)
        result = self.jira.list_tickets("PROJ")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["key"], "PROJ-1")

    @patch("JiraOAuth3LO.requests.get")
    @patch.object(JiraOAuth3LO, 'get_accessible_resources')
    @patch.object(JiraOAuth3LO, 'get_token')
    def test_list_projects(self, mock_get_token, mock_get_accessible_resources, mock_get):
        mock_get_token.return_value = "dummy_token"
        self.jira.cloud_id = "cloud123"
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"values": [
                {"key": "PROJ1", "name": "Project 1"},
                {"key": "PROJ2", "name": "Project 2"}
            ]},
            raise_for_status=lambda: None
        )
        projects = self.jira.list_projects()
        self.assertEqual(len(projects), 2)
        self.assertEqual(projects[0]["key"], "PROJ1")
        self.assertEqual(projects[1]["key"], "PROJ2")

    def test_extract_user_data(self):
        ticket = {
            "fields": {
                "assignee": {"displayName": "John Doe"},
                "reporter": {"displayName": "Jane Smith"},
                "description": "Hello @john.doe, please review.",
                "comment": {"comments": [{"body": "Thanks @jane.smith!"}]}
            }
        }
        user_data = self.jira.extract_user_data(ticket)
        self.assertEqual(user_data["assignee"], "John Doe")
        self.assertEqual(user_data["reporter"], "Jane Smith")
        self.assertIn("john.doe", user_data["mentions"])
        self.assertIn("jane.smith", user_data["mentions"])

    @patch("JiraOAuth3LO.requests.post")
    @patch.object(JiraOAuth3LO, 'get_accessible_resources')
    @patch.object(JiraOAuth3LO, 'get_token')
    def test_add_comment(self, mock_get_token, mock_get_accessible_resources, mock_post):
        mock_get_token.return_value = "dummy_token"
        self.jira.cloud_id = "cloud123"
        mock_post.return_value = MagicMock(status_code=201, json=lambda: {"id": "10001", "body": {"content": []}}, raise_for_status=lambda: None)
        result = self.jira.add_comment("PROJ-1", "Test comment")
        self.assertEqual(result["id"], "10001")

    @patch("JiraOAuth3LO.requests.get")
    @patch.object(JiraOAuth3LO, 'get_accessible_resources')
    @patch.object(JiraOAuth3LO, 'get_token')
    def test_get_comments(self, mock_get_token, mock_get_accessible_resources, mock_get):
        mock_get_token.return_value = "dummy_token"
        self.jira.cloud_id = "cloud123"
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"comments": [{"id": "10001", "body": {"content": []}}]}, raise_for_status=lambda: None)
        comments = self.jira.get_comments("PROJ-1")
        self.assertEqual(len(comments), 1)
        self.assertEqual(comments[0]["id"], "10001")

    def test_react_to_comment(self):
        with self.assertRaises(NotImplementedError):
            self.jira.react_to_comment("10001", ":thumbsup:")

if __name__ == "__main__":
    unittest.main()