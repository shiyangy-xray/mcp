# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""CloudWatch Application Signals MCP Server - AWS client initialization."""

import boto3
import os
from botocore.config import Config
from loguru import logger

from . import __version__


# Get AWS region from environment variable or use default
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
logger.debug(f'Using AWS region: {AWS_REGION}')


def _initialize_aws_clients():
    """Initialize AWS clients with proper configuration."""
    config = Config(user_agent_extra=f'awslabs.cloudwatch-appsignals-mcp-server/{__version__}')
    
    # Get endpoint URLs from environment variables
    appsignals_endpoint = os.environ.get('MCP_APPSIGNALS_ENDPOINT')
    logs_endpoint = os.environ.get('MCP_LOGS_ENDPOINT')
    cloudwatch_endpoint = os.environ.get('MCP_CLOUDWATCH_ENDPOINT')
    xray_endpoint = os.environ.get('MCP_XRAY_ENDPOINT')
    
    # Log endpoint overrides
    if appsignals_endpoint:
        logger.debug(f'Using Application Signals endpoint override: {appsignals_endpoint}')
    if logs_endpoint:
        logger.debug(f'Using CloudWatch Logs endpoint override: {logs_endpoint}')
    if cloudwatch_endpoint:
        logger.debug(f'Using CloudWatch endpoint override: {cloudwatch_endpoint}')
    if xray_endpoint:
        logger.debug(f'Using X-Ray endpoint override: {xray_endpoint}')

    # Check for AWS_PROFILE environment variable
    if aws_profile := os.environ.get('AWS_PROFILE'):
        logger.debug(f'Using AWS profile: {aws_profile}')
        session = boto3.Session(profile_name=aws_profile, region_name=AWS_REGION)
        logs = session.client('logs', config=config, endpoint_url=logs_endpoint)
        appsignals = session.client('application-signals', region_name=AWS_REGION, config=config, endpoint_url=appsignals_endpoint)
        cloudwatch = session.client('cloudwatch', config=config, endpoint_url=cloudwatch_endpoint)
        xray = session.client('xray', config=config, endpoint_url=xray_endpoint)
    else:
        logs = boto3.client('logs', region_name=AWS_REGION, config=config, endpoint_url=logs_endpoint)
        appsignals = boto3.client('application-signals', region_name=AWS_REGION, config=config, endpoint_url=appsignals_endpoint)
        cloudwatch = boto3.client('cloudwatch', region_name=AWS_REGION, config=config, endpoint_url=cloudwatch_endpoint)
        xray = boto3.client('xray', region_name=AWS_REGION, config=config, endpoint_url=xray_endpoint)

    logger.debug('AWS clients initialized successfully')
    return logs, appsignals, cloudwatch, xray


# Initialize clients at module level
try:
    logs_client, appsignals_client, cloudwatch_client, xray_client = _initialize_aws_clients()
except Exception as e:
    logger.error(f'Failed to initialize AWS clients: {str(e)}')
    raise
