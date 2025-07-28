import os
import requests
import redis
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class JiraOAuth3LO:
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
        """
        Exchange authorization code for access and refresh tokens from JIRA.
        """
        url = "https://auth.atlassian.com/oauth/token"
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

    def get_accessible_resources(self, access_token):
        """
        Use the access token to get accessible resources (cloud IDs) from JIRA and store the first cloud_id.
        """
        url = "https://api.atlassian.com/oauth/token/accessible-resources"
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
                
    def refresh_token(self):
        """
        Use the refresh token to obtain a new access token before expiry.
        """
        try:
            token_data = self.load_token()
            if not token_data or 'refresh_token' not in token_data:
                raise Exception("No refresh token available.")
            url = "https://auth.atlassian.com/oauth/token"
            headers = {"Content-Type": "application/json"}
            data = {
                "grant_type": "refresh_token", #authorization code is mandatory - investigate this. Ideally authorization code should also be in redis without expiry.
                "client_id": self.client_id, #If get_token is called with code, then redis should update it's authorization code in cache.
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
        """
        Check if a valid token exists in Redis.
        """
        try:
            token_data = self.redis_client.get(self.token_key)
            if token_data:
                import json
                token_data = json.loads(token_data)
                # Check expiry
                from time import time
                if token_data.get('expires_at', 0) > time():
                    return token_data
            return None
        except Exception as e:
            logger.error(f"Failed to load token from Redis: {e}")
            return None

    def cache_token_to_redis(self, token, expiry):
        """
        Cache the token in Redis with its expiry.
        """
        try:
            import json
            from time import time
            token['expires_at'] = int(time()) + int(expiry)
            self.redis_client.set(self.token_key, json.dumps(token), ex=expiry)
        except Exception as e:
            logger.error(f"Failed to cache token to Redis: {e}")
            raise Exception(f"Failed to cache token to Redis: {e}")

    def get_token(self, code=None):
        """
        Public method to get a valid access token.
        If token exists in Redis and not expired, return it.
        Else refresh token or exchange code, cache it, and return.
        """
        try:
            token_data = self.load_token() #Checking if token is in cache
            if token_data: #token found in cache
                return token_data['access_token']
            elif code: #No token in cache, but authorization code provided
                token_response = self.call_token_api(code)
                self.cache_token_to_redis(token_response, token_response.get('expires_in', 3600))
                return token_response['access_token']
            else: #No token in cache, no authorization code provided, so refresh token - investigate this
                token_response = self.refresh_token()
                return token_response['access_token']
        except Exception as e:
            logger.error(f"Failed to get token: {e}")
            raise Exception(f"Failed to get token: {e}")
