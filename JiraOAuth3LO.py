import os
import requests
import redis
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Atlassian base URLs
ATLASSIAN_AUTH_BASE_URL = "https://auth.atlassian.com"
ATLASSIAN_API_BASE_URL = "https://api.atlassian.com"

class JiraAuthBase:
    def __init__(self, client_id, client_secret, redirect_uri, redis_client=None, redis_host='localhost', redis_port=6379, redis_db=0):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        if redis_client is not None:
            self.redis_client = redis_client
        else:
            self.redis_client = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db, decode_responses=True)
        self.token_key = "jira_oauth_token"
        self.env_token = os.environ.get("JIRA_AUTH_TOKEN")

    def call_token_api(self, code):
        url = f"{ATLASSIAN_AUTH_BASE_URL}/oauth/token"
        headers = {"Content-Type": "application/json"}
        data = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri
        }
        try:
            response = requests.post(url, json=data, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to exchange code for token: {e}")
            raise Exception(f"Failed to exchange code for token: {e}")

    def refresh_token(self):
        try:
            token_data = self.load_token()
            if not token_data or 'refresh_token' not in token_data:
                raise Exception("No refresh token available.")
            url = f"{ATLASSIAN_AUTH_BASE_URL}/oauth/token"
            headers = {"Content-Type": "application/json"}
            data = {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": token_data['refresh_token'],
            }
            response = requests.post(url, json=data, headers=headers)
            response.raise_for_status()
            token_response = response.json()
            self.cache_token_to_redis(token_response, token_response.get('expires_in', 3600))
            return token_response
        except Exception as e:
            logger.error(f"Failed to refresh token: {e}")
            raise Exception(f"Failed to refresh token: {e}")

    def load_token(self):
        try:
            token_data = self.redis_client.get(self.token_key)
            if token_data:
                import json
                token_data = json.loads(token_data)
                from time import time
                if token_data.get('expires_at', 0) > time():
                    return token_data
            return None
        except Exception as e:
            logger.error(f"Failed to load token from Redis: {e}")
            return None

    def cache_token_to_redis(self, token, expiry):
        try:
            import json
            from time import time
            token['expires_at'] = int(time()) + int(expiry)
            self.redis_client.set(self.token_key, json.dumps(token), ex=expiry)
        except Exception as e:
            logger.error(f"Failed to cache token to Redis: {e}")
            raise Exception(f"Failed to cache token to Redis: {e}")

    def get_token(self, code=None):
        try:
            token_data = self.load_token()
            if token_data:
                return token_data['access_token']
            elif code:
                token_response = self.call_token_api(code)
                self.cache_token_to_redis(token_response, token_response.get('expires_in', 3600))
                return token_response['access_token']
            else:
                token_response = self.refresh_token()
                return token_response['access_token']
        except Exception as e:
            logger.error(f"Failed to get token: {e}")
            raise Exception(f"Failed to get token: {e}")

class JiraOAuth3LO(JiraAuthBase):
    def __init__(self, client_id, client_secret, redirect_uri, redis_client=None, redis_host='localhost', redis_port=6379, redis_db=0):
        super().__init__(client_id, client_secret, redirect_uri, redis_client, redis_host, redis_port, redis_db)
        self.cloud_id = None

    def get_accessible_resources(self, access_token):
        url = f"{ATLASSIAN_API_BASE_URL}/oauth/token/accessible-resources"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json"
        }
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            resources = response.json()
            if resources and isinstance(resources, list) and 'id' in resources[0]:
                self.cloud_id = resources[0]['id']
            return resources
        except requests.RequestException as e:
            logger.error(f"Failed to get accessible resources: {e}")
            raise Exception(f"Failed to get accessible resources: {e}")

    def create_ticket(self, data):
        try:
            access_token = self.get_token()
            if not self.cloud_id:
                resources = self.get_accessible_resources(access_token)
                if resources and isinstance(resources, list) and 'id' in resources[0]:
                    self.cloud_id = resources[0]['id']
                else:
                    raise Exception("Could not determine Jira cloud_id.")
            url = f"{ATLASSIAN_API_BASE_URL}/ex/jira/{self.cloud_id}/rest/api/3/issue"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            response = requests.post(url, json=data, headers=headers)
            if response.status_code == 400:
                print("Jira API 400 Bad Request:", response.text)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to create Jira ticket: {e}")
            raise Exception(f"Failed to create Jira ticket: {e}")

    def update_ticket(self, ticket_id, data):
        try:
            access_token = self.get_token()
            if not self.cloud_id:
                resources = self.get_accessible_resources(access_token)
                if resources and isinstance(resources, list) and 'id' in resources[0]:
                    self.cloud_id = resources[0]['id']
                else:
                    raise Exception("Could not determine Jira cloud_id.")
            url = f"{ATLASSIAN_API_BASE_URL}/ex/jira/{self.cloud_id}/rest/api/3/issue/{ticket_id}"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            response = requests.put(url, json=data, headers=headers)
            response.raise_for_status()
            return response.status_code == 204
        except Exception as e:
            logger.error(f"Failed to update Jira ticket: {e}")
            raise Exception(f"Failed to update Jira ticket: {e}")

    def delete_ticket(self, ticket_id):
        try:
            access_token = self.get_token()
            if not self.cloud_id:
                resources = self.get_accessible_resources(access_token)
                if resources and isinstance(resources, list) and 'id' in resources[0]:
                    self.cloud_id = resources[0]['id']
                else:
                    raise Exception("Could not determine Jira cloud_id.")
            url = f"{ATLASSIAN_API_BASE_URL}/ex/jira/{self.cloud_id}/rest/api/3/issue/{ticket_id}"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
            return response.status_code == 204
        except Exception as e:
            logger.error(f"Failed to delete Jira ticket: {e}")
            raise Exception(f"Failed to delete Jira ticket: {e}")

    def get_ticket(self, ticket_id):
        try:
            access_token = self.get_token()
            if not self.cloud_id:
                resources = self.get_accessible_resources(access_token)
                if resources and isinstance(resources, list) and 'id' in resources[0]:
                    self.cloud_id = resources[0]['id']
                else:
                    raise Exception("Could not determine Jira cloud_id.")
            url = f"{ATLASSIAN_API_BASE_URL}/ex/jira/{self.cloud_id}/rest/api/3/issue/{ticket_id}"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get Jira ticket: {e}")
            raise Exception(f"Failed to get Jira ticket: {e}")

    def list_tickets(self, project_key, jql=None):
        try:
            access_token = self.get_token()
            if not self.cloud_id:
                resources = self.get_accessible_resources(access_token)
                if resources and isinstance(resources, list) and 'id' in resources[0]:
                    self.cloud_id = resources[0]['id']
                else:
                    raise Exception("Could not determine Jira cloud_id.")
            url = f"{ATLASSIAN_API_BASE_URL}/ex/jira/{self.cloud_id}/rest/api/3/search"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
            if jql is None:
                jql = f'project={project_key}'
            params = {"jql": jql}
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json().get('issues', [])
        except Exception as e:
            logger.error(f"Failed to list Jira tickets: {e}")
            raise Exception(f"Failed to list Jira tickets: {e}")

    def list_projects(self):
        try:
            access_token = self.get_token()
            if not self.cloud_id:
                resources = self.get_accessible_resources(access_token)
                if resources and isinstance(resources, list) and 'id' in resources[0]:
                    self.cloud_id = resources[0]['id']
                else:
                    raise Exception("Could not determine Jira cloud_id.")
            url = f"{ATLASSIAN_API_BASE_URL}/ex/jira/{self.cloud_id}/rest/api/3/project/search"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json().get('values', [])
        except Exception as e:
            logger.error(f"Failed to list Jira projects: {e}")
            raise Exception(f"Failed to list Jira projects: {e}")

    def extract_user_data(self, ticket):
        user_data = {
            'assignee': None,
            'reporter': None,
            'mentions': set()
        }
        try:
            fields = ticket.get('fields', {})
            assignee = fields.get('assignee')
            if assignee:
                user_data['assignee'] = assignee.get('displayName') or assignee.get('name')
            reporter = fields.get('reporter')
            if reporter:
                user_data['reporter'] = reporter.get('displayName') or reporter.get('name')
            description = fields.get('description', '')
            import re
            if isinstance(description, dict) and 'content' in description:
                def extract_mentions_adf(adf):
                    mentions = set()
                    if isinstance(adf, dict):
                        if adf.get('type') == 'mention' and 'attrs' in adf:
                            mentions.add(adf['attrs'].get('text'))
                        for v in adf.values():
                            if isinstance(v, (dict, list)):
                                mentions.update(extract_mentions_adf(v))
                    elif isinstance(adf, list):
                        for item in adf:
                            mentions.update(extract_mentions_adf(item))
                    return mentions
                user_data['mentions'].update(extract_mentions_adf(description))
            elif isinstance(description, str):
                user_data['mentions'].update(re.findall(r'@([\w.\-]+)', description))
            comments = fields.get('comment', {}).get('comments', [])
            for comment in comments:
                body = comment.get('body', '')
                if isinstance(body, dict):
                    user_data['mentions'].update(extract_mentions_adf(body))
                elif isinstance(body, str):
                    user_data['mentions'].update(re.findall(r'@([\w.\-]+)', body))
            user_data['mentions'] = list(user_data['mentions'])
            return user_data
        except Exception as e:
            logger.error(f"Failed to extract user data: {e}")
            raise Exception(f"Failed to extract user data: {e}")

    def add_comment(self, ticket_id, comment):
        try:
            access_token = self.get_token()
            if not self.cloud_id:
                resources = self.get_accessible_resources(access_token)
                if resources and isinstance(resources, list) and 'id' in resources[0]:
                    self.cloud_id = resources[0]['id']
                else:
                    raise Exception("Could not determine Jira cloud_id.")
            url = f"{ATLASSIAN_API_BASE_URL}/ex/jira/{self.cloud_id}/rest/api/3/issue/{ticket_id}/comment"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            if isinstance(comment, str):
                comment_body = {
                    "body": {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {"type": "text", "text": comment}
                                ]
                            }
                        ]
                    }
                }
            else:
                comment_body = {"body": comment}
            response = requests.post(url, json=comment_body, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to add comment: {e}")
            raise Exception(f"Failed to add comment: {e}")

    def get_comments(self, ticket_id):
        try:
            access_token = self.get_token()
            if not self.cloud_id:
                resources = self.get_accessible_resources(access_token)
                if resources and isinstance(resources, list) and 'id' in resources[0]:
                    self.cloud_id = resources[0]['id']
                else:
                    raise Exception("Could not determine Jira cloud_id.")
            url = f"{ATLASSIAN_API_BASE_URL}/ex/jira/{self.cloud_id}/rest/api/3/issue/{ticket_id}/comment"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json().get('comments', [])
        except Exception as e:
            logger.error(f"Failed to get comments: {e}")
            raise Exception(f"Failed to get comments: {e}")

    def react_to_comment(self, comment_id, reaction):
        logger.warning("Jira Cloud API does not support comment reactions. This is a placeholder.")
        raise NotImplementedError("Jira Cloud API does not support comment reactions.")
