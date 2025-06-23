#!/usr/bin/env python3
"""
Elasticsearch Pre-signed URL Authentication Proxy

This proxy validates AWS pre-signed URLs and forwards authenticated requests to Elasticsearch.

Expected identity format from pre-signed URL validation:
(True, {
    'account': '072422391281',
    'user_id': 'AROARBXFV7XY3ATBAN2B5:payment-es-user',
    'arn': 'arn:aws:sts::072422391281:assumed-role/db-iam-auth-dev-elasticsearch-db-role/payment-es-user'
})
"""

import asyncio
import hashlib
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any

import aiohttp
from aiohttp import web, ClientSession

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AwsStsValidator:
    """Validates AWS pre-signed URLs by calling STS GetCallerIdentity"""

    def __init__(self):
        self.cache = {}
        self.cache_timeout = 300

    async def validate_presigned_url(self, presigned_url: str) -> Optional[Dict[str, Any]]:
        """Validate pre-signed URL and return caller identity"""

        url_hash = hashlib.md5(presigned_url.encode()).hexdigest()
        if url_hash in self.cache:
            cached_entry = self.cache[url_hash]
            if datetime.now().timestamp() < cached_entry['expiry']:
                logger.debug("Cache hit for pre-signed URL validation")
                return cached_entry['identity']
            else:
                del self.cache[url_hash]

        try:
            # Use JSON headers for the request
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }

            async with ClientSession() as session:
                async with session.get(
                        presigned_url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        response_text = await response.text()
                        identity = self._parse_caller_identity(response_text)

                        if identity:
                            self.cache[url_hash] = {
                                'identity': identity,
                                'expiry': datetime.now().timestamp() + self.cache_timeout
                            }

                            logger.info(f"Successfully validated identity: {identity.get('arn', 'unknown')}")
                            return identity
                        else:
                            logger.warning("Failed to parse caller identity from STS response")
                            return None
                    else:
                        logger.warning(f"STS validation failed with status: {response.status}")
                        return None

        except Exception as e:
            logger.error(f"Error validating pre-signed URL: {e}")
            return None

    def _parse_caller_identity(self, response_text: str) -> Optional[Dict[str, Any]]:
        """Parse GetCallerIdentity JSON response and return identity dict"""

        try:
            # Parse JSON response from STS GetCallerIdentity
            data = json.loads(response_text)

            # Handle different possible JSON response formats
            if 'GetCallerIdentityResponse' in data and 'GetCallerIdentityResult' in data['GetCallerIdentityResponse']:
                # Full AWS format: {"GetCallerIdentityResponse": {"GetCallerIdentityResult": {"Account": "...", "UserId": "...", "Arn": "..."}}}
                result = data['GetCallerIdentityResponse']['GetCallerIdentityResult']
                return {
                    'account': result.get('Account', ''),
                    'user_id': result.get('UserId', ''),
                    'arn': result.get('Arn', '')
                }
            elif 'GetCallerIdentityResult' in data:
                # Format: {"GetCallerIdentityResult": {"Account": "...", "UserId": "...", "Arn": "..."}}
                result = data['GetCallerIdentityResult']
                return {
                    'account': result.get('Account', ''),
                    'user_id': result.get('UserId', ''),
                    'arn': result.get('Arn', '')
                }
            elif 'Account' in data and 'UserId' in data and 'Arn' in data:
                # Direct format: {"Account": "...", "UserId": "...", "Arn": "..."}
                return {
                    'account': data.get('Account', ''),
                    'user_id': data.get('UserId', ''),
                    'arn': data.get('Arn', '')
                }
            elif 'account' in data and 'user_id' in data and 'arn' in data:
                # Lowercase format: {"account": "...", "user_id": "...", "arn": "..."}
                return {
                    'account': data.get('account', ''),
                    'user_id': data.get('user_id', ''),
                    'arn': data.get('arn', '')
                }
            else:
                logger.error(f"Unexpected JSON response format: {data}")
                return None

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse STS response as JSON: {e}")
            logger.debug(f"Response content: {response_text}")
            return None
        except Exception as e:
            logger.error(f"Error parsing caller identity: {e}")
            return None


class ElasticsearchProxy:
    """Proxy that handles authentication and forwards requests to Elasticsearch"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.elasticsearch_url = config.get('elasticsearch_url', 'http://localhost:9200').rstrip('/')
        self.sts_validator = AwsStsValidator()
        self.account_id = config.get('aws_account_id', '072422391281')
        self.user_mappings = self._load_user_mappings()

    def _load_user_mappings(self) -> Dict[str, str]:
        """Load user mappings from configuration"""
        return {
            # Map IAM role ARNs to Elasticsearch users
            # Based on the example: arn:aws:sts::072422391281:assumed-role/db-iam-auth-dev-elasticsearch-db-role/payment-es-user
            f'arn:aws:sts::{self.account_id}:assumed-role/db-iam-auth-dev-elasticsearch-db-role/': 'elasticsearch_user',
            f'arn:aws:sts::{self.account_id}:assumed-role/db-iam-auth-prod-elasticsearch-db-role/': 'elasticsearch_user',

            # Admin roles
            f'arn:aws:sts::{self.account_id}:assumed-role/db-iam-auth-admin-elasticsearch-db-role/': 'elasticsearch_admin',
        }

    def _extract_username_from_arn(self, arn: str) -> str:
        """Extract database username from ARN session name"""
        # ARN format: arn:aws:sts::072422391281:assumed-role/db-iam-auth-dev-elasticsearch-db-role/payment-es-user
        try:
            parts = arn.split('/')
            if len(parts) >= 3:
                session_name = parts[-1]
                logger.debug(f"Extracted username '{session_name}' from ARN: {arn}")
                return session_name
            else:
                logger.warning(f"Unexpected ARN format: {arn}")
                return 'default_user'
        except Exception as e:
            logger.error(f"Error extracting username from ARN {arn}: {e}")
            return 'default_user'

    def _map_arn_to_es_user(self, arn: str) -> str:
        """Map IAM role ARN to Elasticsearch user"""

        db_username = self._extract_username_from_arn(arn)

        # Check if this is a valid Elasticsearch database role
        if 'elasticsearch' in arn.lower() and 'db-role' in arn.lower():
            logger.info(f"Mapping Elasticsearch DB role to user: {db_username}")
            return db_username

        # Try exact role pattern matching for other cases
        for role_pattern, es_user in self.user_mappings.items():
            if arn.startswith(role_pattern):
                logger.info(f"Mapping ARN {arn} to predefined user: {es_user}")
                return es_user

        # By default use the session name as the username
        logger.info(f"Using session name as username: {db_username}")
        return db_username

    def _get_es_permissions_for_user(self, username: str, arn: str) -> Dict[str, Any]:
        """Determine Elasticsearch permissions based on username and ARN"""

        # Basic permission mapping based on username patterns
        permissions = {
            'username': username,
            'roles': ['kibana_user'],
            'metadata': {
                'arn': arn,
                'source': 'aws_presigned_url'
            }
        }

        # Add admin permissions for admin users
        if 'admin' in username.lower():
            permissions['roles'] = ['superuser', 'kibana_system']
        # Add read-only permissions for read users
        elif 'read' in username.lower() or 'readonly' in username.lower():
            permissions['roles'] = ['kibana_user', 'viewer']
        # Add write permissions for specific service users
        elif any(service in username.lower() for service in ['payment', 'order', 'inventory']):
            permissions['roles'] = ['kibana_user', 'editor']

        logger.info(f"Assigned permissions for user {username}: {permissions['roles']}")
        return permissions

    async def handle_request(self, request: web.Request) -> web.Response:
        """Handle incoming requests"""

        # Check for pre-signed URL authentication
        auth_header = request.headers.get('Authorization', '')

        if auth_header.startswith('PreSignedUrl '):
            presigned_url = auth_header[len('PreSignedUrl '):]
            identity = await self.sts_validator.validate_presigned_url(presigned_url)

            if identity and identity.get('arn'):
                # Extract the database username from the ARN session name
                arn = identity['arn']
                es_username = self._map_arn_to_es_user(arn)

                # Get permissions for this user
                permissions = self._get_es_permissions_for_user(es_username, arn)

                # Log authentication details for audit purposes
                logger.info(f"Authenticated request from ARN: {arn}")
                logger.info(f"Database user: {es_username}")
                logger.info(f"Account: {identity.get('account', 'unknown')}")
                logger.info(f"User ID: {identity.get('user_id', 'unknown')}")

                # Forward request to Elasticsearch without authentication
                return await self._forward_to_elasticsearch(request, identity=identity, permissions=permissions)
            else:
                logger.warning("Pre-signed URL validation failed")
                return web.Response(
                    status=401,
                    text=json.dumps({
                        "error": "Invalid pre-signed URL",
                        "message": "Failed to validate AWS STS identity"
                    }),
                    content_type='application/json'
                )

        # For requests without pre-signed URL auth, deny access
        logger.warning(f"Request without valid authentication: {request.method} {request.path}")
        return web.Response(
            status=401,
            text=json.dumps({
                "error": "Authentication required",
                "message": "Please provide 'Authorization: PreSignedUrl <url>' header"
            }),
            content_type='application/json'
        )

    async def _forward_to_elasticsearch(self, request: web.Request,
                                        identity: Dict[str, Any] = None,
                                        permissions: Dict[str, Any] = None) -> web.Response:
        """Forward request to Elasticsearch"""

        headers = dict(request.headers)

        # Remove the custom Authorization header since ES doesn't understand it
        if 'Authorization' in headers and headers['Authorization'].startswith('PreSignedUrl'):
            del headers['Authorization']

        if identity:
            headers['X-AWS-Account'] = identity.get('account', '')
            headers['X-AWS-User-ID'] = identity.get('user_id', '')
            headers['X-AWS-ARN'] = identity.get('arn', '')

        if permissions:
            headers['X-ES-Username'] = permissions.get('username', '')
            headers['X-ES-Roles'] = ','.join(permissions.get('roles', []))

        hop_by_hop = ['connection', 'keep-alive', 'proxy-authenticate',
                      'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade']
        for header in hop_by_hop:
            headers.pop(header, None)

        target_url = f"{self.elasticsearch_url}{request.path_qs}"

        try:
            async with ClientSession() as session:
                async with session.request(
                        method=request.method,
                        url=target_url,
                        headers=headers,
                        data=await request.read() if request.can_read_body else None,
                        timeout=aiohttp.ClientTimeout(total=30)
                ) as response:

                    body = await response.read()

                    response_headers = {}
                    for name, value in response.headers.items():
                        if name.lower() not in hop_by_hop:
                            response_headers[name] = value

                    # Add audit information to response headers
                    if identity:
                        response_headers['X-Auth-Method'] = 'aws-presigned-url'
                        response_headers['X-Auth-User'] = permissions.get('username', '') if permissions else ''

                    if identity:
                        logger.info(
                            f"Proxied request - User: {permissions.get('username', 'unknown') if permissions else 'unknown'}, "
                            f"Method: {request.method}, Path: {request.path}, "
                            f"Status: {response.status}, Account: {identity.get('account', 'unknown')}")

                    return web.Response(
                        body=body,
                        status=response.status,
                        headers=response_headers
                    )

        except Exception as e:
            logger.error(f"Error forwarding request to Elasticsearch: {e}")
            return web.Response(
                status=502,
                text=json.dumps({"error": "Bad Gateway", "message": str(e)}),
                content_type='application/json'
            )


def load_config():
    """Load configuration"""
    config = {
        "aws_account_id": "072422391281",

        "elasticsearch_url": "http://localhost:9200",
        "proxy_port": 9201,

        "cache_timeout_seconds": 300,
    }

    try:
        import os
        config_file = os.path.join(os.path.dirname(__file__), 'config.json')
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                file_config = json.load(f)
                config.update(file_config)
                logger.info(f"Loaded configuration from {config_file}")
    except Exception as e:
        logger.warning(f"Could not load config file: {e}, using defaults")

    return config


def create_app() -> web.Application:
    """Create the proxy application"""
    config = load_config()
    proxy = ElasticsearchProxy(config)
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', proxy.handle_request)
    return app


async def main():
    """Main entry point"""
    config = load_config()
    app = create_app()

    runner = web.AppRunner(app)
    await runner.setup()

    proxy_port = config.get('proxy_port', 9201)
    elasticsearch_url = config.get('elasticsearch_url', 'http://localhost:9200')

    site = web.TCPSite(runner, '0.0.0.0', proxy_port)
    await site.start()

    logger.info(f"Elasticsearch proxy started on http://0.0.0.0:{proxy_port}")
    logger.info(f"Forwarding requests to {elasticsearch_url}")
    logger.info(f"AWS Account ID: {config.get('aws_account_id')}")
    logger.info("Send requests with 'Authorization: PreSignedUrl <url>' header")

    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await runner.cleanup()


if __name__ == '__main__':
    asyncio.run(main())