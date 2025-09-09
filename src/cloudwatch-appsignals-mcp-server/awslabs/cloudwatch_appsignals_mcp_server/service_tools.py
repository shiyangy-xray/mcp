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

"""CloudWatch Application Signals MCP Server - Service-related tools."""

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from loguru import logger
from pydantic import Field
from time import perf_counter as timer
from typing import Optional

from .aws_clients import appsignals_client, cloudwatch_client
from .utils import parse_timestamp


async def list_monitored_services() -> str:
    """OPTIONAL TOOL for service discovery - audit_service_health() can automatically discover services using wildcard patterns.

    **WHEN TO USE THIS TOOL:**
    - Getting a detailed overview of all monitored services in your environment
    - Discovering specific service names and environments for manual audit target construction
    - Understanding the complete service inventory before targeted analysis
    - When you need detailed service attributes beyond what wildcard expansion provides

    **RECOMMENDED WORKFLOW:**
    - **Primary**: Use `audit_service_health()` with wildcard patterns like `[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*"}}}]` for automatic service discovery
    - **Alternative**: Use this tool first if you need detailed service information, then construct specific audit targets

    **AUTOMATIC SERVICE DISCOVERY IN AUDIT:**
    The `audit_service_health()` tool automatically discovers services when you use wildcard patterns:
    - `[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*"}}}]` - Audits all services
    - `[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*payment*"}}}]` - Audits services with "payment" in the name

    Returns a formatted list showing:
    - Service name and type  
    - Key attributes (Name, Environment, Platform, etc.)
    - Total count of services

    **NOTE**: The audit_service_health() tool can automatically discover and audit services without requiring this tool first.
    """
    start_time_perf = timer()
    logger.debug('Starting list_application_signals_services request')

    try:
        # Calculate time range (last 24 hours)
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=24)

        # Get all services
        logger.debug(f'Querying services for time range: {start_time} to {end_time}')
        response = appsignals_client.list_services(
            StartTime=start_time, EndTime=end_time, MaxResults=100
        )
        services = response.get('ServiceSummaries', [])
        logger.debug(f'Retrieved {len(services)} services from Application Signals')

        if not services:
            logger.warning('No services found in Application Signals')
            return 'No services found in Application Signals.'

        result = f'Application Signals Services ({len(services)} total):\n\n'

        for service in services:
            # Extract service name from KeyAttributes
            key_attrs = service.get('KeyAttributes', {})
            service_name = key_attrs.get('Name', 'Unknown')
            service_type = key_attrs.get('Type', 'Unknown')

            result += f'• Service: {service_name}\n'
            result += f'  Type: {service_type}\n'

            # Add key attributes
            if key_attrs:
                result += '  Key Attributes:\n'
                for key, value in key_attrs.items():
                    result += f'    {key}: {value}\n'

            result += '\n'

        elapsed_time = timer() - start_time_perf
        logger.debug(f'list_monitored_services completed in {elapsed_time:.3f}s')
        return result

    except Exception as e:
        logger.error(f'Unexpected error in list_monitored_services: {str(e)}', exc_info=True)
        return f'Error: {str(e)}'


async def get_service_detail(
    service_name: str = Field(
        ..., description='Name of the service to get details for (case-sensitive)'
    ),
) -> str:
    """Get detailed information about a specific Application Signals service.

    Use this tool when you need to:
    - Understand a service's configuration and setup
    - Understand where this servive is deployed and where it is running such as EKS, Lambda, etc.
    - See what metrics are available for a service
    - Find log groups associated with the service
    - Get service metadata and attributes

    Returns comprehensive details including:
    - Key attributes (Type, Environment, Platform)
    - Available CloudWatch metrics with namespaces
    - Metric dimensions and types
    - Associated log groups for debugging

    This tool is essential before querying specific metrics, as it shows
    which metrics are available for the service.
    """
    start_time_perf = timer()
    logger.debug(f'Starting get_service_healthy_detail request for service: {service_name}')

    try:
        # Calculate time range (last 24 hours)
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=24)

        # First, get all services to find the one we want
        services_response = appsignals_client.list_services(
            StartTime=start_time, EndTime=end_time, MaxResults=100
        )

        # Find the service with matching name
        target_service = None
        for service in services_response.get('ServiceSummaries', []):
            key_attrs = service.get('KeyAttributes', {})
            if key_attrs.get('Name') == service_name:
                target_service = service
                break

        if not target_service:
            logger.warning(f"Service '{service_name}' not found in Application Signals")
            return f"Service '{service_name}' not found in Application Signals."

        # Get detailed service information
        logger.debug(f'Getting detailed information for service: {service_name}')
        service_response = appsignals_client.get_service(
            StartTime=start_time, EndTime=end_time, KeyAttributes=target_service['KeyAttributes']
        )

        service_details = service_response['Service']

        # Build detailed response
        result = f'Service Details: {service_name}\n\n'

        # Key Attributes
        key_attrs = service_details.get('KeyAttributes', {})
        if key_attrs:
            result += 'Key Attributes:\n'
            for key, value in key_attrs.items():
                result += f'  {key}: {value}\n'
            result += '\n'

        # Attribute Maps (Platform, Application, Telemetry info)
        attr_maps = service_details.get('AttributeMaps', [])
        if attr_maps:
            result += 'Additional Attributes:\n'
            for attr_map in attr_maps:
                for key, value in attr_map.items():
                    result += f'  {key}: {value}\n'
            result += '\n'

        # Metric References
        metric_refs = service_details.get('MetricReferences', [])
        if metric_refs:
            result += f'Metric References ({len(metric_refs)} total):\n'
            for metric in metric_refs:
                result += f'  • {metric.get("Namespace", "")}/{metric.get("MetricName", "")}\n'
                result += f'    Type: {metric.get("MetricType", "")}\n'
                dimensions = metric.get('Dimensions', [])
                if dimensions:
                    result += '    Dimensions: '
                    dim_strs = [f'{d["Name"]}={d["Value"]}' for d in dimensions]
                    result += ', '.join(dim_strs) + '\n'
                result += '\n'

        # Log Group References
        log_refs = service_details.get('LogGroupReferences', [])
        if log_refs:
            result += f'Log Group References ({len(log_refs)} total):\n'
            for log_ref in log_refs:
                log_group = log_ref.get('Identifier', 'Unknown')
                result += f'  • {log_group}\n'
            result += '\n'

        elapsed_time = timer() - start_time_perf
        logger.debug(f"get_service_detail completed for '{service_name}' in {elapsed_time:.3f}s")
        return result

    except Exception as e:
        logger.error(
            f"Unexpected error in get_service_healthy_detail for '{service_name}': {str(e)}",
            exc_info=True,
        )
        return f'Error: {str(e)}'


async def query_service_metrics(
    service_name: str = Field(
        ..., description='Name of the service to get metrics for (case-sensitive)'
    ),
    metric_name: str = Field(
        ...,
        description='Specific metric name (e.g., Latency, Error, Fault). Leave empty to list available metrics',
    ),
    statistic: str = Field(
        default='Average',
        description='Standard statistic type (Average, Sum, Maximum, Minimum, SampleCount)',
    ),
    extended_statistic: str = Field(
        default='p99', description='Extended statistic (p99, p95, p90, p50, etc)'
    ),
    hours: int = Field(
        default=1, description='Number of hours to look back (default 1, max 168 for 1 week)'
    ),
) -> str:
    """Get CloudWatch metrics for a specific Application Signals service.

    Use this tool to:
    - Analyze service performance (latency, throughput)
    - Check error rates and reliability
    - View trends over time
    - Get both standard statistics (Average, Max) and percentiles (p99, p95)

    Common metric names:
    - 'Latency': Response time in milliseconds
    - 'Error': Percentage of failed requests
    - 'Fault': Percentage of server errors (5xx)

    Returns:
    - Summary statistics (latest, average, min, max)
    - Recent data points with timestamps
    - Both standard and percentile values when available

    The tool automatically adjusts the granularity based on time range:
    - Up to 3 hours: 1-minute resolution
    - Up to 24 hours: 5-minute resolution
    - Over 24 hours: 1-hour resolution
    """
    start_time_perf = timer()
    logger.info(
        f'Starting query_service_metrics request - service: {service_name}, metric: {metric_name}, hours: {hours}'
    )

    try:
        # Calculate time range
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)

        # Get service details to find metrics
        services_response = appsignals_client.list_services(
            StartTime=start_time, EndTime=end_time, MaxResults=100
        )

        # Find the target service
        target_service = None
        for service in services_response.get('ServiceSummaries', []):
            key_attrs = service.get('KeyAttributes', {})
            if key_attrs.get('Name') == service_name:
                target_service = service
                break

        if not target_service:
            logger.warning(f"Service '{service_name}' not found in Application Signals")
            return f"Service '{service_name}' not found in Application Signals."

        # Get detailed service info for metric references
        service_response = appsignals_client.get_service(
            StartTime=start_time, EndTime=end_time, KeyAttributes=target_service['KeyAttributes']
        )

        metric_refs = service_response['Service'].get('MetricReferences', [])

        if not metric_refs:
            logger.warning(f"No metrics found for service '{service_name}'")
            return f"No metrics found for service '{service_name}'."

        # If no specific metric requested, show available metrics
        if not metric_name:
            result = f"Available metrics for service '{service_name}':\n\n"
            for metric in metric_refs:
                result += f'• {metric.get("MetricName", "Unknown")}\n'
                result += f'  Namespace: {metric.get("Namespace", "Unknown")}\n'
                result += f'  Type: {metric.get("MetricType", "Unknown")}\n'
                result += '\n'
            return result

        # Find the specific metric
        target_metric = None
        for metric in metric_refs:
            if metric.get('MetricName') == metric_name:
                target_metric = metric
                break

        if not target_metric:
            available = [m.get('MetricName', 'Unknown') for m in metric_refs]
            return f"Metric '{metric_name}' not found for service '{service_name}'. Available: {', '.join(available)}"

        # Calculate appropriate period based on time range
        if hours <= 3:
            period = 60  # 1 minute
        elif hours <= 24:
            period = 300  # 5 minutes
        else:
            period = 3600  # 1 hour

        # Get both standard and extended statistics in a single call
        response = cloudwatch_client.get_metric_statistics(
            Namespace=target_metric['Namespace'],
            MetricName=target_metric['MetricName'],
            Dimensions=target_metric.get('Dimensions', []),
            StartTime=start_time,
            EndTime=end_time,
            Period=period,
            Statistics=[statistic],  # type: ignore
            ExtendedStatistics=[extended_statistic],
        )

        datapoints = response.get('Datapoints', [])

        if not datapoints:
            logger.warning(
                f"No data points found for metric '{metric_name}' on service '{service_name}' in the last {hours} hour(s)"
            )
            return f"No data points found for metric '{metric_name}' on service '{service_name}' in the last {hours} hour(s)."

        # Sort by timestamp
        datapoints.sort(key=lambda x: x.get('Timestamp', datetime.min))  # type: ignore

        # Build response
        result = f'Metrics for {service_name} - {metric_name}\n'
        result += f'Time Range: Last {hours} hour(s)\n'
        result += f'Period: {period} seconds\n\n'

        # Calculate summary statistics for both standard and extended statistics
        standard_values = [dp.get(statistic) for dp in datapoints if dp.get(statistic) is not None]
        extended_values = [
            dp.get(extended_statistic)
            for dp in datapoints
            if dp.get(extended_statistic) is not None
        ]

        result += 'Summary:\n'

        if standard_values:
            latest_standard = datapoints[-1].get(statistic)
            avg_of_standard = sum(standard_values) / len(standard_values)  # type: ignore
            max_standard = max(standard_values)  # type: ignore
            min_standard = min(standard_values)  # type: ignore

            result += f'{statistic} Statistics:\n'
            result += f'• Latest: {latest_standard:.2f}\n'
            result += f'• Average: {avg_of_standard:.2f}\n'
            result += f'• Maximum: {max_standard:.2f}\n'
            result += f'• Minimum: {min_standard:.2f}\n\n'

        if extended_values:
            latest_extended = datapoints[-1].get(extended_statistic)
            avg_extended = sum(extended_values) / len(extended_values)  # type: ignore
            max_extended = max(extended_values)  # type: ignore
            min_extended = min(extended_values)  # type: ignore

            result += f'{extended_statistic} Statistics:\n'
            result += f'• Latest: {latest_extended:.2f}\n'
            result += f'• Average: {avg_extended:.2f}\n'
            result += f'• Maximum: {max_extended:.2f}\n'
            result += f'• Minimum: {min_extended:.2f}\n\n'

        result += f'• Data Points: {len(datapoints)}\n\n'

        # Show recent values (last 10) with both metrics
        result += 'Recent Values:\n'
        for dp in datapoints[-10:]:
            timestamp = dp.get('Timestamp', datetime.min).strftime('%m/%d %H:%M')  # type: ignore
            unit = dp.get('Unit', '')

            values_str = []
            if dp.get(statistic) is not None:
                values_str.append(f'{statistic}: {dp[statistic]:.2f}')
            if dp.get(extended_statistic) is not None:
                values_str.append(f'{extended_statistic}: {dp[extended_statistic]:.2f}')

            result += f'• {timestamp}: {", ".join(values_str)} {unit}\n'

        elapsed_time = timer() - start_time_perf
        logger.info(
            f"query_service_metrics completed for '{service_name}/{metric_name}' in {elapsed_time:.3f}s"
        )
        return result

    except Exception as e:
        logger.error(
            f"Unexpected error in query_service_metrics for '{service_name}/{metric_name}': {str(e)}",
            exc_info=True,
        )
        return f'Error: {str(e)}'
