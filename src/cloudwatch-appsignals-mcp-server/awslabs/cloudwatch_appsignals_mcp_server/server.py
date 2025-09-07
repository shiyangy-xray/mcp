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

"""CloudWatch Application Signals MCP Server - Core server implementation."""

import asyncio
import boto3
import json
import os
import shutil
import sys
import tempfile
from . import __version__
from .sli_report_client import AWSConfig, SLIReportClient
from botocore.config import Config
from botocore.exceptions import ClientError
from datetime import datetime, timedelta, timezone
from loguru import logger
from mcp.server.fastmcp import FastMCP
from pydantic import Field
from time import perf_counter as timer
from typing import Dict, Optional


# Initialize FastMCP server
mcp = FastMCP('cloudwatch-appsignals')

# Configure logging
log_level = os.environ.get('MCP_CLOUDWATCH_APPSIGNALS_LOG_LEVEL', 'INFO').upper()
logger.remove()  # Remove default handler
logger.add(sys.stderr, level=log_level)

# Add file logging to aws_cli.log
log_file_path = os.environ.get('AUDITOR_LOG_PATH', '/tmp')
try:
    if log_file_path.endswith(os.sep) or os.path.isdir(log_file_path):
        os.makedirs(log_file_path, exist_ok=True)
        aws_cli_log_path = os.path.join(log_file_path, "aws_cli.log")
    else:
        os.makedirs(os.path.dirname(log_file_path) or ".", exist_ok=True)
        aws_cli_log_path = log_file_path
except Exception:
    os.makedirs("/tmp", exist_ok=True)
    aws_cli_log_path = "/tmp/aws_cli.log"

# Add file handler for all logs
logger.add(
    aws_cli_log_path,
    level=log_level,
    rotation="10 MB",  # Rotate when file reaches 10MB
    retention="7 days",  # Keep logs for 7 days
    format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} - {message}",
    enqueue=True  # Thread-safe logging
)

logger.debug(f'CloudWatch AppSignals MCP Server initialized with log level: {log_level}')
logger.debug(f'File logging enabled: {aws_cli_log_path}')

# Get AWS region from environment variable or use default
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
logger.debug(f'Using AWS region: {AWS_REGION}')


# Initialize AWS clients
def _initialize_aws_clients():
    """Initialize AWS clients with proper configuration."""
    config = Config(user_agent_extra=f'awslabs.cloudwatch-appsignals-mcp-server/{__version__}')
    
    # Get endpoint URL from environment variable
    endpoint_url = os.environ.get('MCP_APPSIGNALS_ENDPOINT')
    if endpoint_url:
        logger.debug(f'Using Application Signals endpoint override: {endpoint_url}')

    # Check for AWS_PROFILE environment variable
    if aws_profile := os.environ.get('AWS_PROFILE'):
        logger.debug(f'Using AWS profile: {aws_profile}')
        session = boto3.Session(profile_name=aws_profile, region_name=AWS_REGION)
        logs = session.client('logs', config=config)
        appsignals = session.client('application-signals', region_name=AWS_REGION, config=config, endpoint_url=endpoint_url)
        cloudwatch = session.client('cloudwatch', config=config)
        xray = session.client('xray', config=config)
    else:
        logs = boto3.client('logs', region_name=AWS_REGION, config=config)
        appsignals = boto3.client('application-signals', region_name=AWS_REGION, config=config, endpoint_url=endpoint_url)
        cloudwatch = boto3.client('cloudwatch', region_name=AWS_REGION, config=config)
        xray = boto3.client('xray', region_name=AWS_REGION, config=config)

    logger.debug('AWS clients initialized successfully')
    return logs, appsignals, cloudwatch, xray


# Initialize clients at module level
try:
    logs_client, appsignals_client, cloudwatch_client, xray_client = _initialize_aws_clients()
except Exception as e:
    logger.error(f'Failed to initialize AWS clients: {str(e)}')
    raise


def remove_null_values(data: dict) -> dict:
    """Remove keys with None values from a dictionary.

    Args:
        data: Dictionary to clean

    Returns:
        Dictionary with None values removed
    """
    return {k: v for k, v in data.items() if v is not None}


def parse_timestamp(timestamp_str: str, default_hours: int = 24) -> datetime:
    """Parse timestamp string into datetime object.

    Args:
        timestamp_str: Timestamp in unix seconds or 'YYYY-MM-DD HH:MM:SS' format
        default_hours: Default hours to subtract from now if parsing fails

    Returns:
        datetime object in UTC timezone
    """
    try:
        # Ensure we have a string
        if not isinstance(timestamp_str, str):
            timestamp_str = str(timestamp_str)
            
        # Try parsing as unix timestamp first
        if timestamp_str.isdigit():
            return datetime.fromtimestamp(int(timestamp_str), tz=timezone.utc)

        # Try parsing as ISO format
        if 'T' in timestamp_str:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))

        # Try parsing as 'YYYY-MM-DD HH:MM:SS' format
        return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        # Fallback to default
        return datetime.now(timezone.utc) - timedelta(hours=default_hours)


def calculate_name_similarity(target_name: str, candidate_name: str, name_type: str = "service") -> int:
    """Calculate similarity score between target name and candidate name.
    
    Args:
        target_name: The name the user is looking for
        candidate_name: A candidate name from the API
        name_type: Type of name being matched ("service" or "slo")
        
    Returns:
        Similarity score (0-100, higher is better match)
    """
    target_lower = target_name.lower().strip()
    candidate_lower = candidate_name.lower().strip()
    
    # Handle empty strings
    if not target_lower or not candidate_lower:
        return 0
    
    # Exact match (case insensitive)
    if target_lower == candidate_lower:
        return 100
    
    # Normalize for special characters (treat -, _, . as equivalent)
    target_normalized = target_lower.replace('_', '-').replace('.', '-')
    candidate_normalized = candidate_lower.replace('_', '-').replace('.', '-')
    
    if target_normalized == candidate_normalized:
        return 95
    
    score = 0
    
    # Word-based matching (most important for fuzzy matching)
    target_words = set(target_normalized.split())
    candidate_words = set(candidate_normalized.split())
    
    if target_words and candidate_words:
        common_words = target_words.intersection(candidate_words)
        if common_words:
            # Calculate word match ratio
            word_match_ratio = len(common_words) / len(target_words.union(candidate_words))
            score += int(word_match_ratio * 60)  # Up to 60 points for word matches
            
            # Bonus for high word overlap
            target_coverage = len(common_words) / len(target_words)
            candidate_coverage = len(common_words) / len(candidate_words)
            
            if target_coverage >= 0.8:  # 80% of target words found
                score += 20
            elif target_coverage >= 0.6:  # 60% of target words found
                score += 10
    
    # Substring matching (secondary)
    if target_normalized in candidate_normalized:
        # Target is contained in candidate
        containment_ratio = len(target_normalized) / len(candidate_normalized)
        score += int(containment_ratio * 30)  # Up to 30 points
    elif candidate_normalized in target_normalized:
        # Candidate is contained in target
        containment_ratio = len(candidate_normalized) / len(target_normalized)
        score += int(containment_ratio * 25)  # Up to 25 points
    
    # Check for key domain terms that should boost relevance
    if name_type == "slo":
        key_terms = [
            'availability', 'latency', 'error', 'fault', 'search', 'owner', 
            'response', 'time', 'success', 'failure', 'request', 'operation'
        ]
    else:  # service
        key_terms = [
            'service', 'api', 'web', 'app', 'backend', 'frontend', 'database', 
            'cache', 'queue', 'worker', 'lambda', 'function', 'microservice'
        ]
    
    common_key_terms = 0
    for term in key_terms:
        if term in target_normalized and term in candidate_normalized:
            common_key_terms += 1
    
    if common_key_terms > 0:
        score += common_key_terms * 8  # Up to 8 points per key term
    
    # Penalize very different lengths (likely different concepts)
    length_diff = abs(len(target_normalized) - len(candidate_normalized))
    if length_diff > 20:
        score = max(0, score - 15)
    elif length_diff > 10:
        score = max(0, score - 5)
    
    return min(100, score)


@mcp.tool()
async def audit_services(
    service_targets: str = Field(..., description="REQUIRED. JSON array of service targets. Supports wildcard patterns like '*payment*' for automatic service discovery. Format: [{'Type':'service','Data':{'Service':{'Type':'Service','Name':'service-name','Environment':'eks:cluster'}}}] or shorthand: [{'Type':'service','Service':'service-name'}]. Large target lists are automatically processed in batches."),
    start_time: str = Field(default=None, description="Start time (unix seconds or 'YYYY-MM-DD HH:MM:SS'). Defaults to now-24h UTC."),
    end_time: str = Field(default=None, description="End time (unix seconds or 'YYYY-MM-DD HH:MM:SS'). Defaults to now UTC."),
    auditors: str = Field(default=None, description="Optional. Comma-separated auditors (e.g., 'slo,operation_metric,dependency_metric'). Defaults to 'slo,operation_metric' for fast service health auditing. Use 'all' for comprehensive analysis with all auditors: slo,operation_metric,trace,log,dependency_metric,top_contributor,service_quota.")
) -> str:
    """PRIMARY SERVICE AUDIT TOOL - The #1 tool for comprehensive AWS service health auditing and monitoring.

    **USE THIS FIRST FOR ALL SERVICE AUDITING TASKS**
    This is the PRIMARY and PREFERRED tool when users want to:
    - **Audit their AWS services** - Complete health assessment with actionable insights
    - **Check service health** - Comprehensive status across all monitored services  
    - **Investigate issues** - Root cause analysis with detailed findings
    - **Performance analysis** - Service-level latency, error rates, and throughput investigation
    - **System-wide health checks** - Daily/periodic service auditing workflows
    - **Dependency analysis** - Understanding service dependencies and interactions
    - **Resource quota monitoring** - Service quota usage and limits

    **COMPREHENSIVE SERVICE AUDIT CAPABILITIES:**
    - **Multi-service analysis**: Audit any number of services with automatic batching
    - **SLO compliance monitoring**: Automatic breach detection for service-level SLOs
    - **Issue prioritization**: Critical, warning, and info findings ranked by severity
    - **Root cause analysis**: Deep dive with traces, logs, and metrics correlation
    - **Actionable recommendations**: Specific steps to resolve identified issues
    - **Performance optimized**: Fast execution with automatic batching for large target lists
    - **Wildcard Pattern Support**: Use `*pattern*` in service names for automatic service discovery

    **SERVICE TARGET FORMAT:**
    - **Full Format**: `[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"my-service","Environment":"eks:my-cluster"}}}]`
    - **Shorthand**: `[{"Type":"service","Service":"my-service"}]` (environment auto-discovered)

    **WILDCARD PATTERN EXAMPLES:**
    - **All Services**: `[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*"}}}]`
    - **Payment Services**: `[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*payment*"}}}]`
    - **Lambda Services**: `[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*lambda*"}}}]`
    - **EKS Services**: `[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*","Environment":"eks:*"}}}]`

    **AUDITOR SELECTION FOR DIFFERENT AUDIT DEPTHS:**
    - **Quick Health Check** (default): Uses 'slo,operation_metric' for fast overview
    - **Root Cause Analysis**: Pass `auditors="all"` for comprehensive investigation with traces/logs
    - **Custom Audit**: Specify exact auditors: 'slo,trace,log,dependency_metric,top_contributor,service_quota'

    **SERVICE AUDIT USE CASES:**

    1. **Audit all services**: 
       `service_targets='[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*"}}}]'`

    2. **Audit specific service**: 
       `service_targets='[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"orders-service","Environment":"eks:orders-cluster"}}}]'`

    3. **Audit payment services**: 
       `service_targets='[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*payment*"}}}]'`

    8. **Audit lambda services**: 
       `service_targets='[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*lambda*"}}}]'` or by environment: `[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*","Environment":"lambda"}}}]`

    9. **Audit service last night**: 
       `service_targets='[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"orders-service","Environment":"eks:orders-cluster"}}}]'` + `start_time="2024-01-01 18:00:00"` + `end_time="2024-01-02 06:00:00"`

    10. **Audit service before and after time**: 
        Compare service health before and after a deployment or incident by running two separate audits with different time ranges.

    11. **Trace availability issues in production services**: 
        `service_targets='[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*","Environment":"eks:*"}}}]'` + `auditors="all"`

    13. **Look for errors in logs of payment services**: 
        `service_targets='[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*payment*"}}}]'` + `auditors="log,trace"`

    14. **Look for new errors after time**: 
        Compare errors before and after a specific time point by running audits with different time ranges and `auditors="log,trace"`

    15. **Look for errors after deployment**: 
        `service_targets='[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*payment*"}}}]'` + `auditors="log,trace"` + recent time range

    16. **Look for lemon hosts in production**: 
        `service_targets='[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*","Environment":"eks:*"}}}]'` + `auditors="top_contributor,operation_metric"`

    17. **Look for outliers in EKS services**: 
        `service_targets='[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*","Environment":"eks:*"}}}]'` + `auditors="top_contributor,operation_metric"`

    18. **Status report**: 
        `service_targets='[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*"}}}]'` (basic health check)

    19. **Audit dependencies**: 
        `service_targets='[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*"}}}]'` + `auditors="dependency_metric,trace"`

    20. **Audit dependency on S3**: 
        `service_targets='[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*"}}}]'` + `auditors="dependency_metric"` + look for S3 dependencies

    21. **Audit quota usage of tier 1 services**: 
        `service_targets='[{"Type":"service","Data":{"Service":{"Type":"Service","Name":"*tier1*"}}}]'` + `auditors="service_quota,operation_metric"`

    **TYPICAL SERVICE AUDIT WORKFLOWS:**
    1. **Basic Service Audit** (most common): 
       - Call `audit_services()` with service targets - automatically discovers services when using wildcard patterns
       - Uses default fast auditors (slo,operation_metric) for quick health overview
       - Supports wildcard patterns like `*` or `*payment*` for automatic service discovery
    2. **Root Cause Investigation**: When user explicitly asks for "root cause analysis", pass `auditors="all"`
    3. **Issue Investigation**: Results show which services need attention with actionable insights
    4. **Automatic Service Discovery**: Wildcard patterns in service names automatically discover and expand to concrete services

    **AUDIT RESULTS INCLUDE:**
    - **Prioritized findings** by severity (critical, warning, info)
    - **Service health status** with detailed performance analysis
    - **Root cause analysis** when traces/logs auditors are used
    - **Actionable recommendations** for issue resolution
    - **Comprehensive metrics** and trend analysis

    **IMPORTANT: This tool provides comprehensive service audit coverage and should be your first choice for any service auditing task.**
    """
    start_time_perf = timer()
    logger.debug("Starting audit_service_health (PRIMARY SERVICE AUDIT TOOL)")

    try:
        # ---------- Region defaults ----------
        region = AWS_REGION.strip()

        # ---------- Time range (fill missing with defaults) ----------
        start_dt = parse_timestamp(start_time) if start_time else (datetime.now(timezone.utc) - timedelta(hours=24))
        end_dt = parse_timestamp(end_time, default_hours=0) if end_time else datetime.now(timezone.utc)
        unix_start, unix_end = int(start_dt.timestamp()), int(end_dt.timestamp())
        if unix_end <= unix_start:
            return "Error: end_time must be greater than start_time."

        # ---------- Helpers ----------
        def _ci_get(d: dict, *names):
            for n in names:
                if n in d:
                    return d[n]
            lower = {k.lower(): v for k, v in d.items()}
            for n in names:
                if n.lower() in lower:
                    return lower[n.lower()]
            return None

        def _need(d: dict, *names):
            v = _ci_get(d, *names)
            if v is None:
                raise ValueError(f"Missing required field: one of {', '.join(names)}")
            return v

        # ---------- Tolerant coercion for service targets (handles shorthands) ----------
        def _coerce_service_target(t: dict) -> dict:
            """Convert common shorthand inputs into canonical service target with union wrapper:
            Emits: {"Type":"service","Data":{"Service":{"Type":"Service","Name":...,"Environment":...,"AwsAccountId?":...}}}
            Shorthands accepted:
              {"Type":"service","Service":"<name>"}
              {"Type":"service","Data":{"Service":"<name>"}}
              {"Type":"service","Data":{"Service":{"Name":"<name>"}}}
              {"target_type":"service","service":"<name>"}
            """
            ttype = (_ci_get(t, "Type", "type", "target_type") or "").lower()
            if ttype != "service":
                raise ValueError("not a service target")

            data = _ci_get(t, "Data", "data") or {}
            service = _ci_get(data, "Service", "service") or _ci_get(t, "Service", "service")

            if isinstance(service, str):
                entity = {"Name": service}
            elif isinstance(service, dict):
                entity = dict(service)
            elif isinstance(data, dict) and _ci_get(data, "Name", "name"):
                entity = {"Name": _ci_get(data, "Name", "name")}
            else:
                raise ValueError("service target missing 'Service' payload")

            if "Type" not in entity and "type" not in entity:
                entity["Type"] = "Service"

            name = _ci_get(entity, "Name", "name")
            env  = _ci_get(entity, "Environment", "environment")
            acct = _ci_get(entity, "AwsAccountId", "awsAccountId", "aws_account_id")

            out = {"Type": "Service"}
            if name:
                out["Name"] = name
            if env:
                out["Environment"] = env
            if acct:
                out["AwsAccountId"] = acct

            return {"Type": "service", "Data": {"Service": out}}

        # ---------- Strict normalizers (emit lowercase wrapper keys for outer type/data) ----------
        def _normalize_service_entity(entity: dict) -> dict:
            out = {
                "Type": _ci_get(entity, "Type", "type") or "Service",
                "Name": _need(entity, "Name", "name"),
                "Environment": _ci_get(entity, "Environment", "environment"),  # validated later if present
            }
            acct = _ci_get(entity, "AwsAccountId", "awsAccountId", "aws_account_id")
            if acct: out["AwsAccountId"] = acct
            return out

        def _normalize_service(item: dict) -> dict:
            data = _need(item, "Data", "data")
            svc = _ci_get(data, "Service", "service")
            svc_entity = _normalize_service_entity(svc if isinstance(svc, dict) else data)
            return {"Type": "service", "Data": {"Service": svc_entity}}

        def _normalize_slo(item: dict) -> dict:
            data = _need(item, "Data", "data")
            # Accept string or object with SloArn/SloName
            if isinstance(data, str):
                slo_obj = {"SloName": data}
            elif isinstance(data, dict):
                # Check for nested Slo object first (enriched format)
                if "Slo" in data:
                    nested_slo = data["Slo"]
                    if isinstance(nested_slo, dict):
                        slo_arn = _ci_get(nested_slo, "SloArn", "sloArn", "sloarn")
                        slo_name = _ci_get(nested_slo, "SloName", "sloName", "sloname")
                        if slo_arn or slo_name:
                            slo_obj = {"SloArn": slo_arn} if slo_arn else {"SloName": slo_name}
                        else:
                            raise ValueError("SLO target must include SloArn or SloName")
                    else:
                        raise ValueError("SLO Data.Slo must be an object")
                else:
                    # Direct format (not nested)
                    slo_arn = _ci_get(data, "SloArn", "sloArn", "sloarn")
                    slo_name = _ci_get(data, "SloName", "sloName", "sloname")
                    if not (slo_arn or slo_name):
                        raise ValueError("SLO target must include SloArn or SloName")
                    slo_obj = {"SloArn": slo_arn} if slo_arn else {"SloName": slo_name}
            else:
                raise ValueError("SLO Data must be a string or object")
            # Union wrapper REQUIRED by the API: data.slo = {...}
            return {"Type": "slo", "Data": {"Slo": slo_obj}}

        def _normalize_service_op(item: dict) -> dict:
            data = _need(item, "Data", "data")
            
            # Handle both formats: direct Service under Data, or nested under ServiceOperation
            service_operation = _ci_get(data, "ServiceOperation", "serviceOperation")
            if service_operation:
                # Nested format: Data.ServiceOperation.Service
                svc = _need(service_operation, "Service", "service")
                op = _ci_get(service_operation, "Operation", "operation")
                metric_type = _ci_get(service_operation, "MetricType", "metricType") or "Latency"
            else:
                # Direct format: Data.Service
                svc = _need(data, "Service", "service")
                op = _ci_get(data, "Operation", "operation")
                metric_type = _ci_get(data, "MetricType", "metricType") or "Latency"
            
            svc_entity = _normalize_service_entity(svc)
            if not op:
                raise ValueError("service_operation requires Operation")
            
            # Union wrapper REQUIRED: data.ServiceOperation = {...}
            return {
                "Type": "service_operation",
                "Data": {
                    "ServiceOperation": {
                        "Service": svc_entity,
                        "Operation": op,
                        "MetricType": metric_type
                    }
                }
            }

        def _normalize_targets(raw: list) -> list:
            if not isinstance(raw, list):
                raise ValueError("`audit_targets` must be a JSON array")
            if len(raw) == 0:
                raise ValueError("`audit_targets` must contain at least 1 item")
            out = []
            for i, t in enumerate(raw, 1):
                if not isinstance(t, dict):
                    raise ValueError(f"audit_targets[{i}] must be an object")

                maybe_type = (_ci_get(t, "Type", "type", "target_type") or "").lower()
                if maybe_type == "service":
                    try:
                        t = _coerce_service_target(t)  # tolerant upgrade
                    except ValueError as e:
                        raise ValueError(f"audit_targets[{i}] invalid service target: {e}")

                ttype = (_ci_get(t, "Type", "type") or "").lower()
                if ttype == "service":
                    out.append(_normalize_service(t))
                elif ttype == "slo":
                    out.append(_normalize_slo(t))
                elif ttype == "service_operation":
                    out.append(_normalize_service_op(t))
                else:
                    raise ValueError(f"audit_targets[{i}].type must be 'service'|'slo'|'service_operation'")
            return out

        def _validate_and_enrich_targets(normalized_targets: list) -> list:
            """If a service target exists without Environment, or SLO target without SloArn/SloName, fetch from the API.
            
            NOTE: This function should only be called AFTER wildcard expansion has been completed.
            Wildcard patterns should be expanded by expand_wildcard_targets() before calling this function.
            """
            enriched_targets = []
            
            for idx, t in enumerate(normalized_targets, 1):
                target_type = (t.get("Type") or "").lower()
                
                if target_type == "service":
                    svc = ((t.get("Data") or {}).get("Service") or {})
                    service_name = svc.get("Name")
                    
                    # Check if this is still a wildcard pattern - this should not happen after proper expansion
                    if service_name and '*' in service_name:
                        raise ValueError(
                            f"audit_targets[{idx}]: Wildcard pattern '{service_name}' found in validation phase. "
                            f"Wildcard expansion should have been completed before validation. "
                            f"This indicates an internal processing error."
                        )
                    
                    if not svc.get("Environment") and service_name:
                        # Fetch service details from API to get environment
                        logger.debug(f"Fetching environment for service: {service_name}")
                        try:
                            # Get all services to find the one we want
                            services_response = appsignals_client.list_services(
                                StartTime=datetime.fromtimestamp(unix_start, tz=timezone.utc),
                                EndTime=datetime.fromtimestamp(unix_end, tz=timezone.utc),
                                MaxResults=100
                            )
                            
                            # Find the service with matching name
                            target_service = None
                            for service in services_response.get('ServiceSummaries', []):
                                key_attrs = service.get('KeyAttributes', {})
                                if key_attrs.get('Name') == service_name:
                                    target_service = service
                                    break
                            
                            if target_service:
                                key_attrs = target_service.get('KeyAttributes', {})
                                environment = key_attrs.get('Environment')
                                if environment:
                                    # Enrich the service target with the found environment
                                    enriched_svc = dict(svc)
                                    enriched_svc["Environment"] = environment
                                    enriched_target = {
                                        "Type": "service",
                                        "Data": {"Service": enriched_svc}
                                    }
                                    enriched_targets.append(enriched_target)
                                    logger.debug(f"Enriched service {service_name} with environment: {environment}")
                                    continue
                                else:
                                    raise ValueError(
                                        f"audit_targets[{idx}]: Service '{service_name}' found but has no Environment. "
                                        f"This service may not be properly configured in Application Signals."
                                    )
                            else:
                                raise ValueError(
                                    f"audit_targets[{idx}]: Service '{service_name}' not found in Application Signals. "
                                    f"Use list_monitored_services() to see available services."
                                )
                        except Exception as e:
                            if "not found" in str(e) or "Service" in str(e):
                                raise e  # Re-raise our custom error messages
                            else:
                                raise ValueError(
                                    f"audit_targets[{idx}].Data.Service.Environment is required for service targets. "
                                    f"Provide Environment (e.g., 'eks:top-observations/default') or ensure the service exists in Application Signals. "
                                    f"API error: {str(e)}"
                                )
                    elif not svc.get("Environment"):
                        raise ValueError(
                            f"audit_targets[{idx}].Data.Service.Environment is required for service targets. "
                            f"Provide Environment (e.g., 'eks:top-observations/default')."
                        )
                
                elif target_type == "slo":
                    data = t.get("Data", {})
                    
                    # Check if SLO target needs field name normalization (lowercase to uppercase)
                    if isinstance(data, dict) and not data.get("Slo"):
                        # Direct format like {"sloName": "slo-1"} - normalize to uppercase
                        slo_arn = _ci_get(data, "SloArn", "sloArn", "sloarn")
                        slo_name = _ci_get(data, "SloName", "sloName", "sloname")
                        
                        if slo_arn or slo_name:
                            # Normalize to proper format with uppercase field names
                            enriched_target = {
                                "Type": "slo",
                                "Data": {"SloArn": slo_arn} if slo_arn else {"SloName": slo_name}
                            }
                            enriched_targets.append(enriched_target)
                            logger.debug(f"Normalized SLO target field names: {enriched_target}")
                            continue
                        else:
                            # Look for any field that might be an SLO identifier
                            potential_name = _ci_get(data, "Name", "name", "Id", "id")
                            if potential_name:
                                enriched_target = {
                                    "Type": "slo",
                                    "Data": {"SloName": potential_name}
                                }
                                enriched_targets.append(enriched_target)
                                logger.debug(f"Enriched SLO target with SloName from identifier: {potential_name}")
                                continue
                            
                            # If we still can't find an identifier, raise an error
                            raise ValueError(
                                f"audit_targets[{idx}]: SLO target must include SloArn or SloName. "
                                f"Provide either SloArn (ARN) or SloName (name) for the SLO target."
                            )
                    elif isinstance(data, str):
                        # String format - convert to proper format
                        enriched_target = {
                            "Type": "slo",
                            "Data": {"SloName": data}
                        }
                        enriched_targets.append(enriched_target)
                        logger.debug(f"Enriched SLO target from string: {data}")
                        continue
                
                # Add the target as-is if it doesn't need enrichment
                enriched_targets.append(t)
            
            return enriched_targets

        # ---------- Parse & normalize REQUIRED service_targets ----------
        try:
            provided = json.loads(service_targets)
        except json.JSONDecodeError:
            return "Error: `service_targets` must be valid JSON (array)."
        
        # Unified wildcard expansion for both services and SLOs
        def expand_wildcard_targets(targets: list) -> list:
            """Expand wildcard patterns and fuzzy match inexact names for both service and SLO targets."""
            expanded_targets = []
            service_patterns = []
            service_fuzzy_matches = []
            slo_patterns = []
            slo_fuzzy_matches = []
            
            # First pass: identify patterns and collect non-wildcard targets
            for target in targets:
                if not isinstance(target, dict):
                    expanded_targets.append(target)
                    continue
                    
                target_type = target.get('Type', '').lower()
                
                if target_type == 'service':
                    service_data = target.get('Data', {}).get('Service', {})
                    service_name = service_data.get('Name', '')
                    if isinstance(service_name, str):
                        if '*' in service_name:
                            service_patterns.append((target, service_name))
                        else:
                            # Check if this might be a fuzzy match candidate
                            service_fuzzy_matches.append((target, service_name))
                    else:
                        expanded_targets.append(target)
                        
                elif target_type == 'slo':
                    slo_data = target.get('Data', {})
                    # Handle both direct SloName and nested Slo object
                    if isinstance(slo_data, str):
                        if '*' in slo_data:
                            slo_patterns.append((target, slo_data))
                        else:
                            # Check if this might be a fuzzy match candidate
                            slo_fuzzy_matches.append((target, slo_data))
                    elif 'Slo' in slo_data:
                        slo_obj = slo_data['Slo']
                        if isinstance(slo_obj, dict):
                            slo_name = slo_obj.get('SloName', '')
                            if isinstance(slo_name, str):
                                if '*' in slo_name:
                                    slo_patterns.append((target, slo_name))
                                else:
                                    # Check if this might be a fuzzy match candidate
                                    slo_fuzzy_matches.append((target, slo_name))
                            else:
                                expanded_targets.append(target)
                        else:
                            expanded_targets.append(target)
                    else:
                        # Check for direct SloName/SloArn in data
                        slo_name = _ci_get(slo_data, "SloName", "sloName", "sloname")
                        if slo_name and isinstance(slo_name, str):
                            if '*' in slo_name:
                                slo_patterns.append((target, slo_name))
                            else:
                                slo_fuzzy_matches.append((target, slo_name))
                        else:
                            expanded_targets.append(target)
                elif target_type == 'service_operation':
                    # Handle service_operation targets with wildcard expansion
                    service_op_data = target.get('Data', {}).get('ServiceOperation', {})
                    service_data = service_op_data.get('Service', {})
                    service_name = service_data.get('Name', '')
                    operation_name = service_op_data.get('Operation', '')
                    
                    if isinstance(service_name, str) and '*' in service_name:
                        # Service name has wildcards - expand to concrete services first
                        service_patterns.append((target, service_name))
                    elif isinstance(operation_name, str) and '*' in operation_name:
                        # Operation name has wildcards - need to expand operations for the service
                        # For now, pass through as-is since operation expansion requires service-specific logic
                        expanded_targets.append(target)
                    else:
                        # No wildcards in service_operation target
                        expanded_targets.append(target)
                else:
                    # Other target types
                    expanded_targets.append(target)
            
            # Expand service patterns and fuzzy matches
            if service_patterns or service_fuzzy_matches:
                logger.debug(f"Expanding {len(service_patterns)} service wildcard patterns and {len(service_fuzzy_matches)} fuzzy matches")
                try:
                    services_response = appsignals_client.list_services(
                        StartTime=datetime.fromtimestamp(unix_start, tz=timezone.utc),
                        EndTime=datetime.fromtimestamp(unix_end, tz=timezone.utc),
                        MaxResults=100
                    )
                    all_services = services_response.get('ServiceSummaries', [])
                    
                    # Handle wildcard patterns
                    for original_target, pattern in service_patterns:
                        search_term = pattern.strip('*').lower() if pattern != '*' else ''
                        matches_found = 0
                        
                        # Check if this is a service_operation target
                        is_service_operation = original_target.get('Type', '').lower() == 'service_operation'
                        
                        for service in all_services:
                            service_attrs = service.get('KeyAttributes', {})
                            service_name = service_attrs.get('Name', '')
                            
                            if search_term == '' or search_term in service_name.lower():
                                if is_service_operation:
                                    # For service_operation targets, preserve the operation and metric type
                                    service_op_data = original_target.get('Data', {}).get('ServiceOperation', {})
                                    operation_name = service_op_data.get('Operation', '')
                                    metric_type = service_op_data.get('MetricType', 'Latency')
                                    
                                    expanded_targets.append({
                                        "Type": "service_operation",
                                        "Data": {
                                            "ServiceOperation": {
                                                "Service": {
                                                    "Type": "Service",
                                                    "Name": service_name,
                                                    "Environment": service_attrs.get('Environment')
                                                },
                                                "Operation": operation_name,
                                                "MetricType": metric_type
                                            }
                                        }
                                    })
                                else:
                                    # Regular service target
                                    expanded_targets.append({
                                        "Type": "service",
                                        "Data": {
                                            "Service": {
                                                "Type": "Service",
                                                "Name": service_name,
                                                "Environment": service_attrs.get('Environment')
                                            }
                                        }
                                    })
                                matches_found += 1
                        
                        target_type_str = "service_operation" if is_service_operation else "service"
                        logger.debug(f"{target_type_str.title()} pattern '{pattern}' expanded to {matches_found} targets")
                    
                    # Handle fuzzy matches for inexact service names
                    for original_target, inexact_name in service_fuzzy_matches:
                        best_matches = []
                        
                        # Calculate similarity scores for all services
                        for service in all_services:
                            service_attrs = service.get('KeyAttributes', {})
                            service_name = service_attrs.get('Name', '')
                            if not service_name:
                                continue
                                
                            score = calculate_name_similarity(inexact_name, service_name, "service")
                            
                            if score >= 30:  # Minimum threshold for consideration
                                best_matches.append((service_name, service_attrs.get('Environment'), score))
                        
                        # Sort by score and take the best matches
                        best_matches.sort(key=lambda x: x[2], reverse=True)
                        
                        if best_matches:
                            # If we have a very high score match (85+), use only that
                            if best_matches[0][2] >= 85:
                                matched_services = [best_matches[0]]
                            else:
                                # Otherwise, take top 3 matches above threshold
                                matched_services = best_matches[:3]
                            
                            logger.info(f"Fuzzy matching service '{inexact_name}' found {len(matched_services)} candidates:")
                            for service_name, environment, score in matched_services:
                                logger.info(f"  - '{service_name}' in '{environment}' (score: {score})")
                                expanded_targets.append({
                                    "Type": "service",
                                    "Data": {
                                        "Service": {
                                            "Type": "Service",
                                            "Name": service_name,
                                            "Environment": environment
                                        }
                                    }
                                })
                        else:
                            logger.warning(f"No fuzzy matches found for service name '{inexact_name}' (no candidates above threshold)")
                            # Keep the original target - let the API handle the error
                            expanded_targets.append(original_target)
                        
                except Exception as e:
                    logger.warning(f"Failed to expand service patterns and fuzzy matches: {e}")
                    # When expansion fails, we need to return an error rather than passing wildcards to validation
                    # This prevents the validation phase from seeing wildcard patterns
                    if service_patterns or service_fuzzy_matches:
                        pattern_names = [pattern for _, pattern in service_patterns] + [name for _, name in service_fuzzy_matches]
                        raise ValueError(
                            f"Failed to expand service wildcard patterns {pattern_names}. "
                            f"This may be due to AWS API access issues or missing services. "
                            f"Error: {str(e)}"
                        )
            
            # Expand SLO patterns and fuzzy matches
            if slo_patterns or slo_fuzzy_matches:
                logger.debug(f"Expanding {len(slo_patterns)} SLO wildcard patterns and {len(slo_fuzzy_matches)} fuzzy matches")
                try:
                    # Use pagination to get all SLOs
                    all_slos = []
                    next_token = None
                    
                    while True:
                        request_params = {
                            'MaxResults': 50,  # API maximum
                            'IncludeLinkedAccounts': True
                        }
                        if next_token:
                            request_params['NextToken'] = next_token
                        
                        slos_response = appsignals_client.list_service_level_objectives(**request_params)
                        batch_slos = slos_response.get('SloSummaries', [])
                        all_slos.extend(batch_slos)
                        
                        next_token = slos_response.get('NextToken')
                        if not next_token:
                            break
                    
                    logger.debug(f"Retrieved {len(all_slos)} total SLOs for pattern expansion and fuzzy matching")
                    
                    # Handle wildcard patterns
                    for original_target, pattern in slo_patterns:
                        search_term = pattern.strip('*').lower() if pattern != '*' else ''
                        matches_found = 0
                        
                        for slo in all_slos:
                            slo_name = slo.get('Name', '')
                            
                            if search_term == '' or search_term in slo_name.lower():
                                expanded_targets.append({
                                    "Type": "slo",
                                    "Data": {
                                        "Slo": {
                                            "SloName": slo_name
                                        }
                                    }
                                })
                                matches_found += 1
                        
                        logger.debug(f"SLO pattern '{pattern}' expanded to {matches_found} targets")
                    
                    # Handle fuzzy matches for inexact SLO names
                    for original_target, inexact_name in slo_fuzzy_matches:
                        best_matches = []
                        
                        # Calculate similarity scores for all SLOs
                        for slo in all_slos:
                            slo_name = slo.get('Name', '')
                            if not slo_name:
                                continue
                                
                            score = calculate_name_similarity(inexact_name, slo_name, "slo")
                            
                            if score >= 30:  # Minimum threshold for consideration
                                best_matches.append((slo_name, score))
                        
                        # Sort by score and take the best matches
                        best_matches.sort(key=lambda x: x[1], reverse=True)
                        
                        if best_matches:
                            # If we have a very high score match (85+), use only that
                            if best_matches[0][1] >= 85:
                                matched_slos = [best_matches[0]]
                            else:
                                # Otherwise, take top 3 matches above threshold
                                matched_slos = best_matches[:3]
                            
                            logger.info(f"Fuzzy matching SLO '{inexact_name}' found {len(matched_slos)} candidates:")
                            for slo_name, score in matched_slos:
                                logger.info(f"  - '{slo_name}' (score: {score})")
                                expanded_targets.append({
                                    "Type": "slo",
                                    "Data": {
                                        "Slo": {
                                            "SloName": slo_name
                                        }
                                    }
                                })
                        else:
                            logger.warning(f"No fuzzy matches found for SLO name '{inexact_name}' (no candidates above threshold)")
                            # Keep the original target - let the API handle the error
                            expanded_targets.append(original_target)
                        
                except Exception as e:
                    logger.warning(f"Failed to expand SLO patterns and fuzzy matches: {e}")
                    # Add original patterns back if expansion fails
                    expanded_targets.extend([target for target, _ in slo_patterns])
                    expanded_targets.extend([target for target, _ in slo_fuzzy_matches])
            
            return expanded_targets
        
        # Apply unified wildcard expansion
        if any('*' in str(target) for target in provided):
            logger.debug("Wildcard patterns detected - applying unified expansion")
            provided = expand_wildcard_targets(provided)
            logger.debug(f"Wildcard expansion completed - {len(provided)} total targets")
        
        # Validate expanded targets before normalization
        if not isinstance(provided, list):
            return "Error: `audit_targets` must be a JSON array"
        if len(provided) == 0:
            return "Error: No services found matching the wildcard pattern. Please check your service names or use list_monitored_services() to see available services."
        
        # Handle large target lists by automatically batching instead of erroring
        if len(provided) > 10:
            logger.info(f"Large target list detected ({len(provided)} targets). Will process in batches automatically.")
        
        normalized_targets = _normalize_targets(provided)
        
        banner = (
            "[MCP-PRIMARY] Application Signals Comprehensive Audit\n"
            f"🎯 Scope: {len(normalized_targets)} target(s) | Region: {region}\n"
            f"⏰ Time: {unix_start}–{unix_end}\n"
        )
        
        # Add batching info to banner if we have many targets
        if len(normalized_targets) > 5:
            banner += f"📦 Batching: Processing {len(normalized_targets)} targets in batches of 5\n"
        
        banner += "\n"

        # Note: slo_identifiers parameter was removed as it's not part of the new focused tool design

        # Validate and enrich targets after any additions
        try:
            normalized_targets = _validate_and_enrich_targets(normalized_targets)
        except ValueError as ve:
            return f"Error in audit_targets: {ve}"

        # ---------- Auditors (explicit or auto; integrated rule) ----------
        auditors_list = None

        # Handle auditors parameter - check if it's a Field annotation object or actual value
        auditors_value = auditors
        
        # Check if auditors is a Pydantic Field annotation object
        if hasattr(auditors, 'annotation') and hasattr(auditors, 'default'):
            # This is a Field annotation object, use the default value
            auditors_value = auditors.default
        
        # If the caller didn't pass auditors, default to fast auditors for basic service auditing
        # Only use all auditors when explicitly requested or when root cause analysis is mentioned
        if auditors_value is None:
            user_prompt_text = os.environ.get("MCP_USER_PROMPT", "") or ""
            wants_root_cause = "root cause" in user_prompt_text.lower()
            # Always default to fast auditors for basic service auditing unless root cause is explicitly requested
            raw_a = ["slo", "operation_metric"] if not wants_root_cause else []
        elif auditors_value is not None and str(auditors_value).lower() == "all":
            # Special case: "all" means use all auditors (empty list to API)
            raw_a = []
        elif auditors_value is not None:
            # Extract the actual value from the auditors parameter
            raw_a = [a.strip() for a in str(auditors_value).split(",") if a.strip()]
        else:
            raw_a = ["slo", "operation_metric"]

        # Validate auditors
        if len(raw_a) == 0:
            # Empty list means use all auditors
            auditors_list = []
        else:
            allowed = {
                "slo", "operation_metric", "trace", "log",
                "dependency_metric", "top_contributor", "service_quota"
            }
            invalid = [a for a in raw_a if a not in allowed]
            if invalid:
                return (
                    f"Invalid auditor(s): {', '.join(invalid)}. "
                    f"Allowed: {', '.join(sorted(allowed))}"
                )
            auditors_list = raw_a

        # ---------- Build CLI input (SCOPED: AuditTargets MUST be non-empty) ----------
        input_obj = {"StartTime": unix_start, "EndTime": unix_end, "AuditTargets": normalized_targets}
        if auditors_list:
            input_obj["Auditors"] = auditors_list

        # Use the banner that was already set above (either natural language or JSON)
        # Don't overwrite it here

        # ---------- Execute CLI with batching (CMH gamma by default) ----------
        aws_bin = os.environ.get("MCP_AWS_CLI", "aws")
        if shutil.which(aws_bin) is None:
            pretty_input = json.dumps(input_obj, indent=2)
            logger.error(
                banner +
                "Result: FAILED to execute AWS CLI (binary not found).\n"
                "Action: Install or set MCP_AWS_CLI to the full path of your aws binary.\n"
                "---- CLI PARAMETERS (JSON) ----\n" + pretty_input + "\n---- END ----\n"
            )
            return (
                banner +
                "Result: FAILED to execute AWS CLI (binary not found). "
                "Install or set MCP_AWS_CLI to the full path of your aws binary."
            )

        # File log path
        desired_log_path = os.environ.get("AUDITOR_LOG_PATH", "/tmp")
        try:
            if desired_log_path.endswith(os.sep) or os.path.isdir(desired_log_path):
                os.makedirs(desired_log_path, exist_ok=True)
                log_path = os.path.join(desired_log_path, "aws_cli.log")
            else:
                os.makedirs(os.path.dirname(desired_log_path) or ".", exist_ok=True)
                log_path = desired_log_path
        except Exception:
            os.makedirs("/tmp", exist_ok=True); log_path = "/tmp/aws_cli.log"

        # ---------- Batch processing if more than 5 targets ----------
        batch_size = 5
        target_batches = []
        
        if len(normalized_targets) > batch_size:
            logger.info(f"Processing {len(normalized_targets)} targets in batches of {batch_size}")
            # Split targets into batches of 5
            for i in range(0, len(normalized_targets), batch_size):
                batch = normalized_targets[i:i + batch_size]
                target_batches.append(batch)
        else:
            # Single batch if 5 or fewer targets
            target_batches.append(normalized_targets)

        all_batch_results = []
        
        for batch_idx, batch_targets in enumerate(target_batches, 1):
            logger.info(f"Processing batch {batch_idx}/{len(target_batches)} with {len(batch_targets)} targets")
            
            # Build CLI input for this batch
            batch_input_obj = {"StartTime": unix_start, "EndTime": unix_end, "AuditTargets": batch_targets}
            if auditors_list:
                batch_input_obj["Auditors"] = auditors_list

            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tf:
                json.dump(batch_input_obj, tf); tf.flush()
                cli_input_arg = f"file://{tf.name}"

            cmd = [
                aws_bin, "application-signals-demo", "list-audit-findings",
                "--cli-input-json", cli_input_arg, "--region", region
            ]
            
            # Add endpoint-url only if it's set
            endpoint_url = os.environ.get('MCP_APPSIGNALS_ENDPOINT')
            if endpoint_url:
                cmd.extend(["--endpoint-url", endpoint_url])

            # ---------- Pretty log: command + params (file + stderr) ----------
            cli_pretty_cmd = " ".join(cmd)
            cli_pretty_input = json.dumps(batch_input_obj, indent=2)

            # Log CLI invocation details using logger
            logger.info("═" * 80)
            logger.info(f"BATCH {batch_idx}/{len(target_batches)} - {datetime.now(timezone.utc).isoformat()}")
            logger.info(banner.strip())
            logger.info("---- CLI INVOCATION ----")
            logger.info(cli_pretty_cmd)
            logger.info("---- CLI PARAMETERS (JSON) ----")
            logger.info(cli_pretty_input)
            logger.info("---- END PARAMETERS ----")
            
            # Enhanced API call payload debug output
            logger.info("🔍 ENHANCED API CALL PAYLOAD DEBUG OUTPUT")
            logger.info("=" * 60)
            logger.info(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
            logger.info(f"Command: {cli_pretty_cmd}")
            logger.info(f"Endpoint: {os.environ.get('MCP_APPSIGNALS_ENDPOINT', 'default')}")
            logger.info(f"Region: {region}")
            logger.info(f"Batch: {batch_idx}/{len(target_batches)}")
            logger.info(f"Targets in batch: {len(batch_targets)}")
            logger.info(f"Auditors: {auditors_list}")
            logger.info(f"Time range: {unix_start} - {unix_end}")
            logger.info("--- FULL PAYLOAD JSON ---")
            logger.info(cli_pretty_input)
            logger.info("--- END PAYLOAD ---")
            logger.info("=" * 60)

            logger.info("\n" + "═" * 80)
            logger.info(f"BATCH {batch_idx}/{len(target_batches)}")
            logger.info(banner.strip("\n"))
            logger.info("---- CLI INVOCATION ----")
            logger.info(cli_pretty_cmd)
            logger.info("---- CLI PARAMETERS (JSON) ----")
            logger.info("\n" + cli_pretty_input)
            logger.info("---- END PARAMETERS ----")

            # Run the CLI for this batch
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_b, stderr_b = await proc.communicate()
            stdout, stderr = stdout_b.decode("utf-8", errors="replace"), stderr_b.decode("utf-8", errors="replace")

            # ---------- Handle CLI execution result for this batch ----------
            if proc.returncode != 0:
                with open(log_path, "a") as f:
                    f.write(f"---- BATCH {batch_idx} CLI RESPONSE (stderr/stdout) ----\n")
                    f.write((stderr or stdout) + "\n")
                    f.write("---- END RESPONSE ----\n\n")
                logger.error(f"---- BATCH {batch_idx} CLI RESPONSE (stderr/stdout) ----\n" + (stderr or stdout) + "\n---- END RESPONSE ----")
                
                # Continue with other batches even if one fails
                batch_error_result = {
                    "batch_index": batch_idx,
                    "error": f"CLI exit code: {proc.returncode}",
                    "stderr_stdout": stderr or stdout,
                    "targets_count": len(batch_targets)
                }
                all_batch_results.append(batch_error_result)
                continue

            # ---------- Format and log output for this batch ----------
            try:
                batch_json = json.loads(stdout)
                observation_text = json.dumps(batch_json, indent=2)
                all_batch_results.append(batch_json)
            except json.JSONDecodeError:
                observation_text = stdout or "<empty>"
                all_batch_results.append({"batch_index": batch_idx, "raw_output": observation_text})

            if not observation_text.strip():
                with open(log_path, "a") as f:
                    f.write(f"📭 Batch {batch_idx}: No findings returned.\n")
                    f.write("---- END RESPONSE ----\n\n")
                logger.info(f"📭 Batch {batch_idx}: No findings returned.\n---- END RESPONSE ----")
            else:
                with open(log_path, "a") as f:
                    f.write(f"---- BATCH {batch_idx} CLI RESPONSE (stdout pretty) ----\n")
                    f.write(observation_text + "\n")
                    f.write("---- END RESPONSE ----\n\n")

                logger.info(f"---- BATCH {batch_idx} CLI RESPONSE (stdout pretty) ----\n" + observation_text + "\n---- END RESPONSE ----")

        # ---------- Aggregate results from all batches ----------
        if not all_batch_results:
            return banner + "Result: No findings from any batch."

        # Aggregate the findings from all successful batches
        aggregated_findings = []
        total_targets_processed = 0
        failed_batches = 0
        
        for batch_result in all_batch_results:
            if isinstance(batch_result, dict):
                if "error" in batch_result:
                    failed_batches += 1
                    continue
                    
                # Extract findings from this batch
                batch_findings = batch_result.get("AuditFindings", [])
                aggregated_findings.extend(batch_findings)
                
                # Count targets processed in this batch
                batch_targets_count = len(batch_result.get("AuditTargets", []))
                total_targets_processed += batch_targets_count

        # Create final aggregated response
        final_result = {
            "AuditFindings": aggregated_findings,
            "BatchSummary": {
                "TotalBatches": len(target_batches),
                "SuccessfulBatches": len(target_batches) - failed_batches,
                "FailedBatches": failed_batches,
                "TotalTargetsProcessed": total_targets_processed,
                "TotalFindingsCount": len(aggregated_findings)
            }
        }

        # Add any error information if there were failed batches
        if failed_batches > 0:
            error_details = []
            for batch_result in all_batch_results:
                if isinstance(batch_result, dict) and "error" in batch_result:
                    error_details.append({
                        "batch": batch_result["batch_index"],
                        "error": batch_result["error"],
                        "targets_count": batch_result["targets_count"]
                    })
            final_result["BatchErrors"] = error_details

        final_observation_text = json.dumps(final_result, indent=2)

        elapsed = timer() - start_time_perf
        logger.debug(f"audit_service_health completed in {elapsed:.3f}s (region={region}) - Processed {len(target_batches)} batches")

        return banner + final_observation_text

    except Exception as e:
        logger.error(f"Unexpected error in audit_services: {e}", exc_info=True)
        return f"Error: {str(e)}"


@mcp.tool()
async def audit_slos(
    slo_targets: str = Field(..., description="REQUIRED. JSON array of SLO targets. Supports wildcard patterns like '*payment*' for automatic SLO discovery. Format: [{'Type':'slo','Data':{'Slo':{'SloName':'slo-name'}}}] or [{'Type':'slo','Data':{'Slo':{'SloArn':'arn:aws:...'}}}]. Large target lists are automatically processed in batches."),
    start_time: str = Field(default=None, description="Start time (unix seconds or 'YYYY-MM-DD HH:MM:SS'). Defaults to now-24h UTC."),
    end_time: str = Field(default=None, description="End time (unix seconds or 'YYYY-MM-DD HH:MM:SS'). Defaults to now UTC."),
    auditors: str = Field(default=None, description="Optional. Comma-separated auditors (e.g., 'slo,trace,log'). Defaults to 'slo' for fast SLO compliance auditing. Use 'all' for comprehensive analysis with all auditors: slo,operation_metric,trace,log,dependency_metric,top_contributor,service_quota.")
) -> str:
    """PRIMARY SLO AUDIT TOOL - The #1 tool for comprehensive SLO compliance monitoring and breach analysis.

    **USE THIS FOR ALL SLO AUDITING TASKS**
    This is the PRIMARY and PREFERRED tool when users want to:
    - **Audit SLO compliance** - Complete SLO breach detection and analysis
    - **Monitor SLO health** - Comprehensive status across all monitored SLOs
    - **Investigate SLO breaches** - Root cause analysis for SLO violations
    - **SLO performance analysis** - Understanding SLO trends and patterns
    - **SLO compliance reporting** - Daily/periodic SLO compliance workflows

    **COMPREHENSIVE SLO AUDIT CAPABILITIES:**
    - **Multi-SLO analysis**: Audit any number of SLOs with automatic batching
    - **Breach detection**: Automatic identification of SLO violations
    - **Issue prioritization**: Critical, warning, and info findings ranked by severity
    - **Root cause analysis**: Deep dive with traces, logs, and metrics correlation when requested
    - **Actionable recommendations**: Specific steps to resolve SLO breaches
    - **Performance optimized**: Fast execution with automatic batching for large target lists
    - **Wildcard Pattern Support**: Use `*pattern*` in SLO names for automatic SLO discovery

    **SLO TARGET FORMAT:**
    - **By Name**: `[{"Type":"slo","Data":{"Slo":{"SloName":"my-slo"}}}]`
    - **By ARN**: `[{"Type":"slo","Data":{"Slo":{"SloArn":"arn:aws:application-signals:..."}}}]`

    **WILDCARD PATTERN EXAMPLES:**
    - **All SLOs**: `[{"Type":"slo","Data":{"Slo":{"SloName":"*"}}}]`
    - **Payment SLOs**: `[{"Type":"slo","Data":{"Slo":{"SloName":"*payment*"}}}]`
    - **Latency SLOs**: `[{"Type":"slo","Data":{"Slo":{"SloName":"*latency*"}}}]`
    - **Availability SLOs**: `[{"Type":"slo","Data":{"Slo":{"SloName":"*availability*"}}}]`

    **AUDITOR SELECTION FOR DIFFERENT AUDIT DEPTHS:**
    - **Quick Compliance Check** (default): Uses 'slo' for fast SLO breach detection
    - **Root Cause Analysis**: Pass `auditors="all"` for comprehensive investigation with traces/logs
    - **Custom Audit**: Specify exact auditors: 'slo,trace,log,operation_metric'

    **SLO AUDIT USE CASES:**

    4. **Audit all SLOs**: 
       `slo_targets='[{"Type":"slo","Data":{"Slo":{"SloName":"*"}}}]'`

    14. **Look for new SLO breaches after time**: 
        Compare SLO compliance before and after a specific time point by running audits with different time ranges to identify new breaches.

    **TYPICAL SLO AUDIT WORKFLOWS:**
    1. **Basic SLO Compliance Audit** (most common): 
       - Call `audit_slos()` with SLO targets - automatically discovers SLOs when using wildcard patterns
       - Uses default fast auditors (slo) for quick compliance overview
       - Supports wildcard patterns like `*` or `*payment*` for automatic SLO discovery
    2. **SLO Breach Investigation**: When user explicitly asks for "root cause analysis", pass `auditors="all"`
    3. **Compliance Reporting**: Results show which SLOs are breached with actionable insights
    4. **Automatic SLO Discovery**: Wildcard patterns in SLO names automatically discover and expand to concrete SLOs

    **AUDIT RESULTS INCLUDE:**
    - **Prioritized findings** by severity (critical, warning, info)
    - **SLO compliance status** with detailed breach analysis
    - **Root cause analysis** when traces/logs auditors are used
    - **Actionable recommendations** for SLO breach resolution
    - **Comprehensive compliance metrics** and trend analysis

    **IMPORTANT: This tool provides comprehensive SLO audit coverage and should be your first choice for any SLO compliance auditing task.**
    """
    start_time_perf = timer()
    logger.debug("Starting audit_slos (PRIMARY SLO AUDIT TOOL)")

    try:
        # Parse and validate SLO targets
        try:
            provided = json.loads(slo_targets)
        except json.JSONDecodeError:
            return "Error: `slo_targets` must be valid JSON (array)."
        
        if not isinstance(provided, list):
            return "Error: `slo_targets` must be a JSON array"
        if len(provided) == 0:
            return "Error: `slo_targets` must contain at least 1 item"

        # Filter to only SLO targets
        slo_only_targets = []
        for target in provided:
            if isinstance(target, dict):
                ttype = target.get("Type", "").lower()
                if ttype == "slo":
                    slo_only_targets.append(target)
                else:
                    logger.warning(f"Ignoring target of type '{ttype}' in audit_slos (expected 'slo')")

        if not slo_only_targets:
            return "Error: No SLO targets found in the provided targets."

        # Handle auditors parameter - check if it's a Field annotation object or actual value
        auditors_value = auditors
        
        # Check if auditors is a Pydantic Field annotation object
        if hasattr(auditors, 'annotation') and hasattr(auditors, 'default'):
            # This is a Field annotation object, use the default value
            auditors_value = auditors.default
        
        # Use the existing audit_services implementation but with SLO-specific processing
        # Convert back to JSON string for the shared implementation
        filtered_targets_json = json.dumps(slo_only_targets)
        
        # Call the existing audit_services implementation with correct parameter handling
        return await audit_services(
            service_targets=filtered_targets_json,
            start_time=start_time,
            end_time=end_time,
            auditors=auditors_value or "slo"  # Default to SLO auditor for SLO auditing
        )

    except Exception as e:
        logger.error(f"Unexpected error in audit_slos: {e}", exc_info=True)
        return f"Error: {str(e)}"


@mcp.tool()
async def audit_service_operations(
    operation_targets: str = Field(..., description="REQUIRED. JSON array of service operation targets. Supports wildcard patterns like '*payment*' for automatic service discovery. Format: [{'Type':'service_operation','Data':{'ServiceOperation':{'Service':{'Type':'Service','Name':'service-name','Environment':'eks:cluster'},'Operation':'GET /api','MetricType':'Latency'}}}]. Large target lists are automatically processed in batches."),
    start_time: str = Field(default=None, description="Start time (unix seconds or 'YYYY-MM-DD HH:MM:SS'). Defaults to now-24h UTC."),
    end_time: str = Field(default=None, description="End time (unix seconds or 'YYYY-MM-DD HH:MM:SS'). Defaults to now UTC."),
    auditors: str = Field(default=None, description="Optional. Comma-separated auditors (e.g., 'operation_metric,trace,log'). Defaults to 'operation_metric' for fast operation-level auditing. Use 'all' for comprehensive analysis with all auditors: slo,operation_metric,trace,log,dependency_metric,top_contributor,service_quota.")
) -> str:
    """SPECIALIZED OPERATION AUDIT TOOL - For detailed operation-level analysis and performance investigation.

    **USE THIS FOR OPERATION-SPECIFIC AUDITING TASKS**
    This is a SPECIALIZED tool when users want to:
    - **Audit specific operations** - Deep dive into individual API endpoints or operations
    - **Operation performance analysis** - Latency, error rates, and throughput for specific operations
    - **Compare operation metrics** - Analyze different operations within services
    - **Operation-level troubleshooting** - Root cause analysis for specific API calls
    - **GET operation auditing** - Analyze GET operations across payment services

    **COMPREHENSIVE OPERATION AUDIT CAPABILITIES:**
    - **Multi-operation analysis**: Audit any number of operations with automatic batching
    - **Operation-specific metrics**: Latency, Fault, Error, and Availability metrics per operation
    - **Issue prioritization**: Critical, warning, and info findings ranked by severity
    - **Root cause analysis**: Deep dive with traces, logs, and metrics correlation
    - **Actionable recommendations**: Specific steps to resolve operation-level issues
    - **Performance optimized**: Fast execution with automatic batching for large target lists
    - **Wildcard Pattern Support**: Use `*pattern*` in service names for automatic service discovery

    **OPERATION TARGET FORMAT:**
    - **Full Format**: `[{"Type":"service_operation","Data":{"ServiceOperation":{"Service":{"Type":"Service","Name":"my-service","Environment":"eks:my-cluster"},"Operation":"GET /api","MetricType":"Latency"}}}]`

    **WILDCARD PATTERN EXAMPLES:**
    - **All GET Operations in Payment Services**: `[{"Type":"service_operation","Data":{"ServiceOperation":{"Service":{"Type":"Service","Name":"*payment*"},"Operation":"*GET*","MetricType":"Latency"}}}]`
    - **All Visit Operations**: `[{"Type":"service_operation","Data":{"ServiceOperation":{"Service":{"Type":"Service","Name":"*"},"Operation":"*visit*","MetricType":"Availability"}}}]`

    **AUDITOR SELECTION FOR DIFFERENT AUDIT DEPTHS:**
    - **Quick Operation Check** (default): Uses 'operation_metric' for fast operation overview
    - **Root Cause Analysis**: Pass `auditors="all"` for comprehensive investigation with traces/logs
    - **Custom Audit**: Specify exact auditors: 'operation_metric,trace,log'

    **OPERATION AUDIT USE CASES:**

    5. **Audit GET operations in payment services (Latency)**: 
       `operation_targets='[{"Type":"service_operation","Data":{"ServiceOperation":{"Service":{"Type":"Service","Name":"*payment*"},"Operation":"*GET*","MetricType":"Latency"}}}]'`

    6. **Audit availability of visit operations**: 
       `operation_targets='[{"Type":"service_operation","Data":{"ServiceOperation":{"Service":{"Type":"Service","Name":"*"},"Operation":"*visit*","MetricType":"Availability"}}}]'`

    7. **Audit latency of visit operations**: 
       `operation_targets='[{"Type":"service_operation","Data":{"ServiceOperation":{"Service":{"Type":"Service","Name":"*"},"Operation":"*visit*","MetricType":"Latency"}}}]'`

    12. **Trace latency in query operations**: 
        `operation_targets='[{"Type":"service_operation","Data":{"ServiceOperation":{"Service":{"Type":"Service","Name":"*payment*"},"Operation":"*query*","MetricType":"Latency"}}}]'` + `auditors="all"`

    **TYPICAL OPERATION AUDIT WORKFLOWS:**
    1. **Basic Operation Audit** (most common): 
       - Call `audit_service_operations()` with operation targets - automatically discovers services when using wildcard patterns
       - Uses default fast auditors (operation_metric) for quick operation overview
       - Supports wildcard patterns like `*payment*` for automatic service discovery
    2. **Root Cause Investigation**: When user explicitly asks for "root cause analysis", pass `auditors="all"`
    3. **Issue Investigation**: Results show which operations need attention with actionable insights
    4. **Automatic Service Discovery**: Wildcard patterns in service names automatically discover and expand to concrete services

    **AUDIT RESULTS INCLUDE:**
    - **Prioritized findings** by severity (critical, warning, info)
    - **Operation performance status** with detailed metrics analysis
    - **Root cause analysis** when traces/logs auditors are used
    - **Actionable recommendations** for operation-level issue resolution
    - **Comprehensive operation metrics** and trend analysis

    **IMPORTANT: This tool provides specialized operation-level audit coverage for detailed performance analysis.**
    """
    start_time_perf = timer()
    logger.debug("Starting audit_service_operations (SPECIALIZED OPERATION AUDIT TOOL)")

    try:
        # Parse and validate operation targets
        try:
            provided = json.loads(operation_targets)
        except json.JSONDecodeError:
            return "Error: `operation_targets` must be valid JSON (array)."
        
        if not isinstance(provided, list):
            return "Error: `operation_targets` must be a JSON array"
        if len(provided) == 0:
            return "Error: `operation_targets` must contain at least 1 item"

        # Filter to only service_operation targets
        operation_only_targets = []
        for target in provided:
            if isinstance(target, dict):
                ttype = target.get("Type", "").lower()
                if ttype == "service_operation":
                    operation_only_targets.append(target)
                else:
                    logger.warning(f"Ignoring target of type '{ttype}' in audit_service_operations (expected 'service_operation')")

        if not operation_only_targets:
            return "Error: No service_operation targets found in the provided targets."

        # Handle auditors parameter - check if it's a Field annotation object or actual value
        auditors_value = auditors
        
        # Check if auditors is a Pydantic Field annotation object
        if hasattr(auditors, 'annotation') and hasattr(auditors, 'default'):
            # This is a Field annotation object, use the default value
            auditors_value = auditors.default

        # Use the existing audit_services implementation but with operation-specific processing
        # Convert back to JSON string for the shared implementation
        filtered_targets_json = json.dumps(operation_only_targets)
        
        # Call the existing audit_services implementation with correct parameter handling
        return await audit_services(
            service_targets=filtered_targets_json,
            start_time=start_time,
            end_time=end_time,
            auditors=auditors_value or "operation_metric"  # Default to operation_metric auditor for operation auditing
        )

    except Exception as e:
        logger.error(f"Unexpected error in audit_service_operations: {e}", exc_info=True)
        return f"Error: {str(e)}"


@mcp.tool()
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

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', 'Unknown error')
        logger.error(f'AWS ClientError in list_monitored_services: {error_code} - {error_message}')
        return f'AWS Error: {error_message}'
    except Exception as e:
        logger.error(f'Unexpected error in list_monitored_services: {str(e)}', exc_info=True)
        return f'Error: {str(e)}'


@mcp.tool()
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

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', 'Unknown error')
        logger.error(
            f"AWS ClientError in get_service_healthy_detail for '{service_name}': {error_code} - {error_message}"
        )
        return f'AWS Error: {error_message}'
    except Exception as e:
        logger.error(
            f"Unexpected error in get_service_healthy_detail for '{service_name}': {str(e)}",
            exc_info=True,
        )
        return f'Error: {str(e)}'


@mcp.tool()
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

    except ClientError as e:
        error_msg = e.response.get('Error', {}).get('Message', 'Unknown error')
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        logger.error(
            f"AWS ClientError in query_service_metrics for '{service_name}/{metric_name}': {error_code} - {error_msg}"
        )
        return f'AWS Error: {error_msg}'
    except Exception as e:
        logger.error(
            f"Unexpected error in query_service_metrics for '{service_name}/{metric_name}': {str(e)}",
            exc_info=True,
        )
        return f'Error: {str(e)}'


def get_trace_summaries_paginated(
    xray_client, start_time, end_time, filter_expression, max_traces: int = 100
) -> list:
    """Get trace summaries with pagination to avoid exceeding response size limits.

    Args:
        xray_client: Boto3 X-Ray client
        start_time: Start time for trace query
        end_time: End time for trace query
        filter_expression: X-Ray filter expression
        max_traces: Maximum number of traces to retrieve (default 100)

    Returns:
        List of trace summaries
    """
    all_traces = []
    next_token = None
    logger.debug(
        f'Starting paginated trace retrieval - filter: {filter_expression}, max_traces: {max_traces}'
    )

    try:
        while len(all_traces) < max_traces:
            # Build request parameters
            kwargs = {
                'StartTime': start_time,
                'EndTime': end_time,
                'FilterExpression': filter_expression,
                'Sampling': True,
                'TimeRangeType': 'Service',
            }

            if next_token:
                kwargs['NextToken'] = next_token

            # Make request
            response = xray_client.get_trace_summaries(**kwargs)

            # Add traces from this page
            traces = response.get('TraceSummaries', [])
            all_traces.extend(traces)
            logger.debug(
                f'Retrieved {len(traces)} traces in this page, total so far: {len(all_traces)}'
            )

            # Check if we have more pages
            next_token = response.get('NextToken')
            if not next_token:
                break

            # If we've collected enough traces, stop
            if len(all_traces) >= max_traces:
                all_traces = all_traces[:max_traces]
                break

        logger.info(f'Successfully retrieved {len(all_traces)} traces')
        return all_traces

    except Exception as e:
        # Return what we have so far if there's an error
        logger.error(f'Error during paginated trace retrieval: {str(e)}', exc_info=True)
        logger.info(f'Returning {len(all_traces)} traces retrieved before error')
        return all_traces


@mcp.tool()
async def get_slo(
    slo_id: str = Field(..., description='The ARN or name of the SLO to retrieve'),
) -> str:
    """Get detailed information about a specific Service Level Objective (SLO).

    Use this tool to:
    - Get comprehensive SLO configuration details
    - Understand what metrics the SLO monitors
    - See threshold values and comparison operators
    - Extract operation names and key attributes for trace queries
    - Identify dependency configurations
    - Review attainment goals and burn rate settings

    Returns detailed information including:
    - SLO name, description, and metadata
    - Metric configuration (for period-based or request-based SLOs)
    - Key attributes and operation names
    - Metric type (LATENCY or AVAILABILITY)
    - Threshold values and comparison operators
    - Goal configuration (attainment percentage, time interval)
    - Burn rate configurations

    This tool is essential for:
    - Understanding why an SLO was breached
    - Getting the exact operation name to query traces
    - Identifying the metrics and thresholds being monitored
    - Planning remediation based on SLO configuration
    """
    start_time_perf = timer()
    logger.info(f'Starting get_service_level_objective request for SLO: {slo_id}')

    try:
        response = appsignals_client.get_service_level_objective(Id=slo_id)
        slo = response.get('Slo', {})

        if not slo:
            logger.warning(f'No SLO found with ID: {slo_id}')
            return f'No SLO found with ID: {slo_id}'

        result = 'Service Level Objective Details\n'
        result += '=' * 50 + '\n\n'

        # Basic info
        result += f'Name: {slo.get("Name", "Unknown")}\n'
        result += f'ARN: {slo.get("Arn", "Unknown")}\n'
        if slo.get('Description'):
            result += f'Description: {slo.get("Description", "")}\n'
        result += f'Evaluation Type: {slo.get("EvaluationType", "Unknown")}\n'
        result += f'Created: {slo.get("CreatedTime", "Unknown")}\n'
        result += f'Last Updated: {slo.get("LastUpdatedTime", "Unknown")}\n\n'

        # Goal configuration
        goal = slo.get('Goal', {})
        if goal:
            result += 'Goal Configuration:\n'
            result += f'• Attainment Goal: {goal.get("AttainmentGoal", 99)}%\n'
            result += f'• Warning Threshold: {goal.get("WarningThreshold", 50)}%\n'

            interval = goal.get('Interval', {})
            if 'RollingInterval' in interval:
                rolling = interval['RollingInterval']
                result += f'• Interval: Rolling {rolling.get("Duration")} {rolling.get("DurationUnit")}\n'
            elif 'CalendarInterval' in interval:
                calendar = interval['CalendarInterval']
                result += f'• Interval: Calendar {calendar.get("Duration")} {calendar.get("DurationUnit")} starting {calendar.get("StartTime")}\n'
            result += '\n'

        # Period-based SLI
        if 'Sli' in slo:
            sli = slo['Sli']
            result += 'Period-Based SLI Configuration:\n'

            sli_metric = sli.get('SliMetric', {})
            if sli_metric:
                # Key attributes - crucial for trace queries
                key_attrs = sli_metric.get('KeyAttributes', {})
                if key_attrs:
                    result += '• Key Attributes:\n'
                    for k, v in key_attrs.items():
                        result += f'  - {k}: {v}\n'

                # Operation name - essential for trace filtering
                if sli_metric.get('OperationName'):
                    result += f'• Operation Name: {sli_metric.get("OperationName", "")}\n'
                    result += f'  (Use this in trace queries: annotation[aws.local.operation]="{sli_metric.get("OperationName", "")}")\n'

                result += f'• Metric Type: {sli_metric.get("MetricType", "Unknown")}\n'

                # MetricDataQueries - detailed metric configuration
                metric_queries = sli_metric.get('MetricDataQueries', [])
                if metric_queries:
                    result += '• Metric Data Queries:\n'
                    for query in metric_queries:
                        query_id = query.get('Id', 'Unknown')
                        result += f'  Query ID: {query_id}\n'

                        # MetricStat details
                        metric_stat = query.get('MetricStat', {})
                        if metric_stat:
                            metric = metric_stat.get('Metric', {})
                            if metric:
                                result += f'    Namespace: {metric.get("Namespace", "Unknown")}\n'
                                result += (
                                    f'    MetricName: {metric.get("MetricName", "Unknown")}\n'
                                )

                                # Dimensions - crucial for understanding what's being measured
                                dimensions = metric.get('Dimensions', [])
                                if dimensions:
                                    result += '    Dimensions:\n'
                                    for dim in dimensions:
                                        result += f'      - {dim.get("Name", "Unknown")}: {dim.get("Value", "Unknown")}\n'

                            result += (
                                f'    Period: {metric_stat.get("Period", "Unknown")} seconds\n'
                            )
                            result += f'    Stat: {metric_stat.get("Stat", "Unknown")}\n'
                            if metric_stat.get('Unit'):
                                result += f'    Unit: {metric_stat["Unit"]}\n'  # type: ignore

                        # Expression if present
                        if query.get('Expression'):
                            result += f'    Expression: {query.get("Expression", "")}\n'

                        result += f'    ReturnData: {query.get("ReturnData", True)}\n'

                # Dependency config
                dep_config = sli_metric.get('DependencyConfig', {})
                if dep_config:
                    result += '• Dependency Configuration:\n'
                    dep_attrs = dep_config.get('DependencyKeyAttributes', {})
                    if dep_attrs:
                        result += '  Key Attributes:\n'
                        for k, v in dep_attrs.items():
                            result += f'    - {k}: {v}\n'
                    if dep_config.get('DependencyOperationName'):
                        result += (
                            f'  - Dependency Operation: {dep_config["DependencyOperationName"]}\n'
                        )
                        result += f'    (Use in traces: annotation[aws.remote.operation]="{dep_config["DependencyOperationName"]}")\n'

            result += f'• Threshold: {sli.get("MetricThreshold", "Unknown")}\n'
            result += f'• Comparison: {sli.get("ComparisonOperator", "Unknown")}\n\n'

        # Request-based SLI
        if 'RequestBasedSli' in slo:
            rbs = slo['RequestBasedSli']
            result += 'Request-Based SLI Configuration:\n'

            rbs_metric = rbs.get('RequestBasedSliMetric', {})
            if rbs_metric:
                # Key attributes
                key_attrs = rbs_metric.get('KeyAttributes', {})
                if key_attrs:
                    result += '• Key Attributes:\n'
                    for k, v in key_attrs.items():
                        result += f'  - {k}: {v}\n'

                # Operation name
                if rbs_metric.get('OperationName'):
                    result += f'• Operation Name: {rbs_metric.get("OperationName", "")}\n'
                    result += f'  (Use this in trace queries: annotation[aws.local.operation]="{rbs_metric.get("OperationName", "")}")\n'

                result += f'• Metric Type: {rbs_metric.get("MetricType", "Unknown")}\n'

                # MetricDataQueries - detailed metric configuration
                metric_queries = rbs_metric.get('MetricDataQueries', [])
                if metric_queries:
                    result += '• Metric Data Queries:\n'
                    for query in metric_queries:
                        query_id = query.get('Id', 'Unknown')
                        result += f'  Query ID: {query_id}\n'

                        # MetricStat details
                        metric_stat = query.get('MetricStat', {})
                        if metric_stat:
                            metric = metric_stat.get('Metric', {})
                            if metric:
                                result += f'    Namespace: {metric.get("Namespace", "Unknown")}\n'
                                result += (
                                    f'    MetricName: {metric.get("MetricName", "Unknown")}\n'
                                )

                                # Dimensions - crucial for understanding what's being measured
                                dimensions = metric.get('Dimensions', [])
                                if dimensions:
                                    result += '    Dimensions:\n'
                                    for dim in dimensions:
                                        result += f'      - {dim.get("Name", "Unknown")}: {dim.get("Value", "Unknown")}\n'

                            result += (
                                f'    Period: {metric_stat.get("Period", "Unknown")} seconds\n'
                            )
                            result += f'    Stat: {metric_stat.get("Stat", "Unknown")}\n'
                            if metric_stat.get('Unit'):
                                result += f'    Unit: {metric_stat["Unit"]}\n'  # type: ignore

                        # Expression if present
                        if query.get('Expression'):
                            result += f'    Expression: {query.get("Expression", "")}\n'

                        result += f'    ReturnData: {query.get("ReturnData", True)}\n'

                # Dependency config
                dep_config = rbs_metric.get('DependencyConfig', {})
                if dep_config:
                    result += '• Dependency Configuration:\n'
                    dep_attrs = dep_config.get('DependencyKeyAttributes', {})
                    if dep_attrs:
                        result += '  Key Attributes:\n'
                        for k, v in dep_attrs.items():
                            result += f'    - {k}: {v}\n'
                    if dep_config.get('DependencyOperationName'):
                        result += (
                            f'  - Dependency Operation: {dep_config["DependencyOperationName"]}\n'
                        )
                        result += f'    (Use in traces: annotation[aws.remote.operation]="{dep_config["DependencyOperationName"]}")\n'

            result += f'• Threshold: {rbs.get("MetricThreshold", "Unknown")}\n'
            result += f'• Comparison: {rbs.get("ComparisonOperator", "Unknown")}\n\n'

        # Burn rate configurations
        burn_rates = slo.get('BurnRateConfigurations', [])
        if burn_rates:
            result += 'Burn Rate Configurations:\n'
            for br in burn_rates:
                result += f'• Look-back window: {br.get("LookBackWindowMinutes")} minutes\n'

        elapsed_time = timer() - start_time_perf
        logger.info(f"get_service_level_objective completed for '{slo_id}' in {elapsed_time:.3f}s")
        return result

    except ClientError as e:
        error_msg = e.response.get('Error', {}).get('Message', 'Unknown error')
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        logger.error(
            f"AWS ClientError in get_service_level_objective for '{slo_id}': {error_code} - {error_msg}"
        )
        return f'AWS Error: {error_msg}'
    except Exception as e:
        logger.error(
            f"Unexpected error in get_service_level_objective for '{slo_id}': {str(e)}",
            exc_info=True,
        )
        return f'Error: {str(e)}'


@mcp.tool()
async def search_transaction_spans(
    log_group_name: str = Field(
        default='',
        description='CloudWatch log group name (defaults to "aws/spans" if not provided)',
    ),
    start_time: str = Field(
        default='', description='Start time in ISO 8601 format (e.g., "2025-04-19T20:00:00+00:00")'
    ),
    end_time: str = Field(
        default='', description='End time in ISO 8601 format (e.g., "2025-04-19T21:00:00+00:00")'
    ),
    query_string: str = Field(default='', description='CloudWatch Logs Insights query string'),
    limit: Optional[int] = Field(default=None, description='Maximum number of results to return'),
    max_timeout: int = Field(
        default=30, description='Maximum time in seconds to wait for query completion'
    ),
) -> Dict:
    """Executes a CloudWatch Logs Insights query for transaction search (100% sampled trace data).

    IMPORTANT: If log_group_name is not provided use 'aws/spans' as default cloudwatch log group name.
    The volume of returned logs can easily overwhelm the agent context window. Always include a limit in the query
    (| limit 50) or using the limit parameter.

    Usage:
    "aws/spans" log group stores OpenTelemetry Spans data with many attributes for all monitored services.
    This provides 100% sampled data vs X-Ray's 5% sampling, giving more accurate results.
    User can write CloudWatch Logs Insights queries to group, list attribute with sum, avg.

    ```
    FILTER attributes.aws.local.service = "customers-service-java" and attributes.aws.local.environment = "eks:demo/default" and attributes.aws.remote.operation="InvokeModel"
    | STATS sum(`attributes.gen_ai.usage.output_tokens`) as `avg_output_tokens` by `attributes.gen_ai.request.model`, `attributes.aws.local.service`,bin(1h)
    | DISPLAY avg_output_tokens, `attributes.gen_ai.request.model`, `attributes.aws.local.service`
    ```

    Returns:
    --------
        A dictionary containing the final query results, including:
            - status: The current status of the query (e.g., Scheduled, Running, Complete, Failed, etc.)
            - results: A list of the actual query results if the status is Complete.
            - statistics: Query performance statistics
            - messages: Any informational messages about the query
            - transaction_search_status: Information about transaction search availability
    """
    start_time_perf = timer()
    logger.info(
        f'Starting search_transactions - log_group: {log_group_name}, start: {start_time}, end: {end_time}'
    )
    logger.debug(f'Query string: {query_string}')

    # Check if transaction search is enabled
    is_enabled, destination, status = check_transaction_search_enabled(AWS_REGION)

    if not is_enabled:
        logger.warning(
            f'Transaction Search not enabled - Destination: {destination}, Status: {status}'
        )
        return {
            'status': 'Transaction Search Not Available',
            'transaction_search_status': {
                'enabled': False,
                'destination': destination,
                'status': status,
            },
            'message': (
                '⚠️ Transaction Search is not enabled for this account. '
                f'Current configuration: Destination={destination}, Status={status}. '
                "Transaction Search requires sending traces to CloudWatch Logs (destination='CloudWatchLogs' and status='ACTIVE'). "
                'Without Transaction Search, you only have access to 5% sampled trace data through X-Ray. '
                'To get 100% trace visibility, please enable Transaction Search in your X-Ray settings. '
                'As a fallback, you can use query_sampled_traces() but results may be incomplete due to sampling.'
            ),
            'fallback_recommendation': 'Use query_sampled_traces() with X-Ray filter expressions for 5% sampled data.',
        }

    try:
        # Use default log group if none provided
        if log_group_name is None:
            log_group_name = 'aws/spans'
            logger.debug('Using default log group: aws/spans')

        # Start query
        kwargs = {
            'startTime': int(datetime.fromisoformat(start_time).timestamp()),
            'endTime': int(datetime.fromisoformat(end_time).timestamp()),
            'queryString': query_string,
            'logGroupNames': [log_group_name],
            'limit': limit,
        }

        logger.debug(f'Starting CloudWatch Logs query with limit: {limit}')
        start_response = logs_client.start_query(**remove_null_values(kwargs))
        query_id = start_response['queryId']
        logger.info(f'Started CloudWatch Logs query with ID: {query_id}')

        # Seconds
        poll_start = timer()
        while poll_start + max_timeout > timer():
            response = logs_client.get_query_results(queryId=query_id)
            status = response['status']

            if status in {'Complete', 'Failed', 'Cancelled'}:
                elapsed_time = timer() - start_time_perf
                logger.info(
                    f'Query {query_id} finished with status {status} in {elapsed_time:.3f}s'
                )

                if status == 'Failed':
                    logger.error(f'Query failed: {response.get("statistics", {})}')
                elif status == 'Complete':
                    logger.debug(f'Query returned {len(response.get("results", []))} results')

                return {
                    'queryId': query_id,
                    'status': status,
                    'statistics': response.get('statistics', {}),
                    'results': [
                        {field.get('field', ''): field.get('value', '') for field in line}  # type: ignore
                        for line in response.get('results', [])
                    ],
                    'transaction_search_status': {
                        'enabled': True,
                        'destination': 'CloudWatchLogs',
                        'status': 'ACTIVE',
                        'message': '✅ Using 100% sampled trace data from Transaction Search',
                    },
                }

            await asyncio.sleep(1)

        elapsed_time = timer() - start_time_perf
        msg = f'Query {query_id} did not complete within {max_timeout} seconds. Use get_query_results with the returned queryId to try again to retrieve query results.'
        logger.warning(f'Query timeout after {elapsed_time:.3f}s: {msg}')
        return {
            'queryId': query_id,
            'status': 'Polling Timeout',
            'message': msg,
        }

    except Exception as e:
        logger.error(f'Error in search_transactions: {str(e)}', exc_info=True)
        raise


@mcp.tool()
async def list_slis(
    hours: int = Field(
        default=24,
        description='Number of hours to look back (default 24, typically use 24 for daily checks)',
    ),
) -> str:
    """SPECIALIZED TOOL - Use audit_service_health() as the PRIMARY tool for service auditing.

    **IMPORTANT: audit_service_health() is the PRIMARY and PREFERRED tool for all service auditing tasks.**
    
    Only use this tool when audit_service_health() cannot handle your specific requirements, such as:
    - Need for legacy SLI status report format specifically
    - Integration with existing systems that expect this exact output format
    - Simple SLI overview without comprehensive audit findings
    - Basic health monitoring dashboard that doesn't need detailed analysis

    **For ALL service auditing, health checks, and issue investigation, use audit_service_health() first.**

    This tool provides a basic report showing:
    - Summary counts (total, healthy, breached, insufficient data)
    - Simple list of breached services with SLO names
    - Basic healthy services list

    Status meanings:
    - OK: All SLOs are being met
    - BREACHED: One or more SLOs are violated
    - INSUFFICIENT_DATA: Not enough data to determine status

    **Recommended workflow**: 
    1. Use audit_service_health() for comprehensive service auditing with actionable insights
    2. Only use this tool if you specifically need the legacy SLI status report format
    """
    start_time_perf = timer()
    logger.info(f'Starting get_sli_status request for last {hours} hours')

    try:
        # Calculate time range
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)
        logger.debug(f'Time range: {start_time} to {end_time}')

        # Get all services
        services_response = appsignals_client.list_services(
            StartTime=start_time,  # type: ignore
            EndTime=end_time,  # type: ignore
            MaxResults=100,
        )
        services = services_response.get('ServiceSummaries', [])

        if not services:
            logger.warning('No services found in Application Signals')
            return 'No services found in Application Signals.'

        # Get SLI reports for each service
        reports = []
        logger.debug(f'Generating SLI reports for {len(services)} services')
        for service in services:
            service_name = service['KeyAttributes'].get('Name', 'Unknown')
            try:
                # Create custom config with the service's key attributes
                config = AWSConfig(
                    region='us-east-1',
                    period_in_hours=hours,
                    service_name=service_name,
                    key_attributes=service['KeyAttributes'],
                )

                # Generate SLI report
                client = SLIReportClient(config)
                sli_report = client.generate_sli_report()

                # Convert to expected format
                report = {
                    'BreachedSloCount': sli_report.breached_slo_count,
                    'BreachedSloNames': sli_report.breached_slo_names,
                    'EndTime': sli_report.end_time.timestamp(),
                    'OkSloCount': sli_report.ok_slo_count,
                    'ReferenceId': {'KeyAttributes': service['KeyAttributes']},
                    'SliStatus': 'BREACHED'
                    if sli_report.sli_status == 'CRITICAL'
                    else sli_report.sli_status,
                    'StartTime': sli_report.start_time.timestamp(),
                    'TotalSloCount': sli_report.total_slo_count,
                }
                reports.append(report)

            except Exception as e:
                # Log error but continue with other services
                logger.error(
                    f'Failed to get SLI report for service {service_name}: {str(e)}', exc_info=True
                )
                # Add a report with insufficient data status
                report = {
                    'BreachedSloCount': 0,
                    'BreachedSloNames': [],
                    'EndTime': end_time.timestamp(),
                    'OkSloCount': 0,
                    'ReferenceId': {'KeyAttributes': service['KeyAttributes']},
                    'SliStatus': 'INSUFFICIENT_DATA',
                    'StartTime': start_time.timestamp(),
                    'TotalSloCount': 0,
                }
                reports.append(report)

        # Check transaction search status
        is_tx_search_enabled, tx_destination, tx_status = check_transaction_search_enabled(
            AWS_REGION
        )

        # Build response
        result = f'SLI Status Report - Last {hours} hours\n'
        result += f'Time Range: {start_time.strftime("%Y-%m-%d %H:%M")} - {end_time.strftime("%Y-%m-%d %H:%M")}\n\n'

        # Add transaction search status
        if is_tx_search_enabled:
            result += '✅ Transaction Search: ENABLED (100% trace visibility available)\n\n'
        else:
            result += '⚠️ Transaction Search: NOT ENABLED (only 5% sampled traces available)\n'
            result += f'   Current config: Destination={tx_destination}, Status={tx_status}\n'
            result += '   Enable Transaction Search for accurate root cause analysis\n\n'

        # Count by status
        status_counts = {
            'OK': sum(1 for r in reports if r['SliStatus'] == 'OK'),
            'BREACHED': sum(1 for r in reports if r['SliStatus'] == 'BREACHED'),
            'INSUFFICIENT_DATA': sum(1 for r in reports if r['SliStatus'] == 'INSUFFICIENT_DATA'),
        }

        result += 'Summary:\n'
        result += f'• Total Services: {len(reports)}\n'
        result += f'• Healthy (OK): {status_counts["OK"]}\n'
        result += f'• Breached: {status_counts["BREACHED"]}\n'
        result += f'• Insufficient Data: {status_counts["INSUFFICIENT_DATA"]}\n\n'

        # Group by status
        if status_counts['BREACHED'] > 0:
            result += '⚠️  BREACHED SERVICES:\n'
            for report in reports:
                if report['SliStatus'] == 'BREACHED':
                    name = report['ReferenceId']['KeyAttributes']['Name']
                    env = report['ReferenceId']['KeyAttributes']['Environment']
                    breached_count = report['BreachedSloCount']
                    total_count = report['TotalSloCount']
                    breached_names = report['BreachedSloNames']

                    result += f'\n• {name} ({env})\n'
                    result += f'  SLOs: {breached_count}/{total_count} breached\n'
                    if breached_names:
                        result += '  Breached SLOs:\n'
                        for slo_name in breached_names:
                            result += f'    - {slo_name}\n'

        if status_counts['OK'] > 0:
            result += '\n✅ HEALTHY SERVICES:\n'
            for report in reports:
                if report['SliStatus'] == 'OK':
                    name = report['ReferenceId']['KeyAttributes']['Name']
                    env = report['ReferenceId']['KeyAttributes']['Environment']
                    ok_count = report['OkSloCount']

                    result += f'• {name} ({env}) - {ok_count} SLO(s) healthy\n'

        if status_counts['INSUFFICIENT_DATA'] > 0:
            result += '\n❓ INSUFFICIENT DATA:\n'
            for report in reports:
                if report['SliStatus'] == 'INSUFFICIENT_DATA':
                    name = report['ReferenceId']['KeyAttributes']['Name']
                    env = report['ReferenceId']['KeyAttributes']['Environment']

                    result += f'• {name} ({env})\n'

        # Remove the auto-investigation feature

        elapsed_time = timer() - start_time_perf
        logger.info(
            f'get_sli_status completed in {elapsed_time:.3f}s - Total: {len(reports)}, Breached: {status_counts["BREACHED"]}, OK: {status_counts["OK"]}'
        )
        return result

    except Exception as e:
        logger.error(f'Error in get_sli_status: {str(e)}', exc_info=True)
        return f'Error getting SLI status: {str(e)}'


def check_transaction_search_enabled(region: str = 'us-east-1') -> tuple[bool, str, str]:
    """Internal function to check if AWS X-Ray Transaction Search is enabled.

    Returns:
        tuple: (is_enabled: bool, destination: str, status: str)
    """
    try:
        response = xray_client.get_trace_segment_destination()

        destination = response.get('Destination', 'Unknown')
        status = response.get('Status', 'Unknown')

        is_enabled = destination == 'CloudWatchLogs' and status == 'ACTIVE'
        logger.debug(
            f'Transaction Search check - Enabled: {is_enabled}, Destination: {destination}, Status: {status}'
        )

        return is_enabled, destination, status

    except Exception as e:
        logger.error(f'Error checking transaction search status: {str(e)}')
        return False, 'Unknown', 'Error'


@mcp.tool()
async def query_sampled_traces(
    start_time: Optional[str] = Field(
        default=None,
        description='Start time in ISO format (e.g., "2024-01-01T00:00:00Z"). Defaults to 3 hours ago',
    ),
    end_time: Optional[str] = Field(
        default=None,
        description='End time in ISO format (e.g., "2024-01-01T01:00:00Z"). Defaults to current time',
    ),
    filter_expression: Optional[str] = Field(
        default=None,
        description='X-Ray filter expression to narrow results (e.g., service("service-name"){fault = true})',
    ),
    region: str = Field(default='us-east-1', description='AWS region (default: us-east-1)'),
) -> str:
    """Query AWS X-Ray traces (5% sampled data) to investigate errors and performance issues.

    ⚠️ IMPORTANT: This tool uses X-Ray's 5% sampled trace data. For 100% trace visibility,
    enable Transaction Search and use search_transaction_spans() instead.

    Use this tool to:
    - Find root causes of errors and faults (with 5% sampling limitations)
    - Analyze request latency and identify bottlenecks
    - Understand the requests across multiple services with traces
    - Debug timeout and dependency issues
    - Understand service-to-service interactions
    - Find customer impact from trace result such as Users data or trace attributes such as owner id

    Common filter expressions:
    - 'service("service-name"){fault = true}': Find all traces with faults (5xx errors) for a service
    - 'service("service-name")': Filter by specific service
    - 'duration > 5': Find slow requests (over 5 seconds)
    - 'http.status = 500': Find specific HTTP status codes
    - 'annotation[aws.local.operation]="GET /owners/*/lastname"': Filter by specific operation (from metric dimensions)
    - 'annotation[aws.remote.operation]="ListOwners"': Filter by remote operation name
    - Combine filters: 'service("api"){fault = true} AND annotation[aws.local.operation]="POST /visits"'

    IMPORTANT: When investigating SLO breaches, use annotation filters with the specific dimension values
    from the breached metric (e.g., Operation, RemoteOperation) to find traces for that exact operation.

    Returns JSON with trace summaries including:
    - Trace ID for detailed investigation
    - Duration and response time
    - Error/fault/throttle status
    - HTTP information (method, status, URL)
    - Service interactions
    - User information if available
    - Exception root causes (ErrorRootCauses, FaultRootCauses, ResponseTimeRootCauses)

    Best practices:
    - Start with recent time windows (last 1-3 hours)
    - Use filter expressions to narrow down issues and query Fault and Error traces for high priority
    - Look for patterns in errors or very slow requests

    Returns:
        JSON string containing trace summaries with error status, duration, and service details
    """
    start_time_perf = timer()
    logger.info(f'Starting query_sampled_traces - region: {region}, filter: {filter_expression}')

    try:
        logger.debug('Using X-Ray client')

        # Default to past 3 hours if times not provided
        if not end_time:
            end_datetime = datetime.now(timezone.utc)
        else:
            end_datetime = datetime.fromisoformat(end_time.replace('Z', '+00:00'))

        if not start_time:
            start_datetime = end_datetime - timedelta(hours=3)
        else:
            start_datetime = datetime.fromisoformat(start_time.replace('Z', '+00:00'))

        # Validate time window to ensure it's not too large (max 6 hours)
        time_diff = end_datetime - start_datetime
        logger.debug(
            f'Query time window: {start_datetime} to {end_datetime} ({time_diff.total_seconds() / 3600:.1f} hours)'
        )
        if time_diff > timedelta(hours=6):
            logger.warning(f'Time window too large: {time_diff.total_seconds() / 3600:.1f} hours')
            return json.dumps(
                {
                    'error': 'Time window too large. Maximum allowed is 6 hours.',
                    'requested_hours': time_diff.total_seconds() / 3600,
                },
                indent=2,
            )

        # Use pagination helper with a reasonable limit
        traces = get_trace_summaries_paginated(
            xray_client,
            start_datetime,
            end_datetime,
            filter_expression or '',
            max_traces=100,  # Limit to prevent response size issues
        )

        # Convert response to JSON-serializable format
        def convert_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            return obj

        trace_summaries = []
        for trace in traces:
            # Create a simplified trace data structure to reduce size
            trace_data = {
                'Id': trace.get('Id'),
                'Duration': trace.get('Duration'),
                'ResponseTime': trace.get('ResponseTime'),
                'HasError': trace.get('HasError'),
                'HasFault': trace.get('HasFault'),
                'HasThrottle': trace.get('HasThrottle'),
                'Http': trace.get('Http', {}),
            }

            # Only include root causes if they exist (to save space)
            if trace.get('ErrorRootCauses'):
                trace_data['ErrorRootCauses'] = trace.get('ErrorRootCauses', [])[
                    :3
                ]  # Limit to first 3
            if trace.get('FaultRootCauses'):
                trace_data['FaultRootCauses'] = trace.get('FaultRootCauses', [])[
                    :3
                ]  # Limit to first 3
            if trace.get('ResponseTimeRootCauses'):
                trace_data['ResponseTimeRootCauses'] = trace.get('ResponseTimeRootCauses', [])[
                    :3
                ]  # Limit to first 3

            # Include limited annotations for key operations
            annotations = trace.get('Annotations', {})
            if annotations:
                # Only include operation-related annotations
                filtered_annotations = {}
                for key in ['aws.local.operation', 'aws.remote.operation']:
                    if key in annotations:
                        filtered_annotations[key] = annotations[key]
                if filtered_annotations:
                    trace_data['Annotations'] = filtered_annotations

            # Include user info if available
            if trace.get('Users'):
                trace_data['Users'] = trace.get('Users', [])[:2]  # Limit to first 2 users

            # Convert any datetime objects to ISO format strings
            for key, value in trace_data.items():
                trace_data[key] = convert_datetime(value)
            trace_summaries.append(trace_data)

        # Check transaction search status
        is_tx_search_enabled, tx_destination, tx_status = check_transaction_search_enabled(region)

        result_data = {
            'TraceSummaries': trace_summaries,
            'TraceCount': len(trace_summaries),
            'Message': f'Retrieved {len(trace_summaries)} traces (limited to prevent size issues)',
            'SamplingNote': "⚠️ This data is from X-Ray's 5% sampling. Results may not show all errors or issues.",
            'TransactionSearchStatus': {
                'enabled': is_tx_search_enabled,
                'recommendation': (
                    'Transaction Search is available! Use search_transaction_spans() for 100% trace visibility.'
                    if is_tx_search_enabled
                    else 'Enable Transaction Search for 100% trace visibility instead of 5% sampling.'
                ),
            },
        }

        elapsed_time = timer() - start_time_perf
        logger.info(
            f'query_sampled_traces completed in {elapsed_time:.3f}s - retrieved {len(trace_summaries)} traces'
        )
        return json.dumps(result_data, indent=2)

    except Exception as e:
        logger.error(f'Error in query_sampled_traces: {str(e)}', exc_info=True)
        return json.dumps({'error': str(e)}, indent=2)


@mcp.tool()
async def list_slos(
    key_attributes: str = Field(
        default="{}",
        description='JSON string of key attributes to filter SLOs (e.g., \'{"Name": "my-service", "Environment": "ecs:my-cluster"}\'. Defaults to empty object to list all SLOs.'
    ),
    include_linked_accounts: bool = Field(
        default=True,
        description='Whether to include SLOs from linked accounts (default: True)'
    ),
    max_results: int = Field(
        default=50,
        description='Maximum number of SLOs to return (default: 50, max: 50)'
    )
) -> str:
    """List all Service Level Objectives (SLOs) in Application Signals.

    Use this tool to:
    - Get a complete list of all SLOs in your account
    - Discover SLO names and ARNs for use with other tools
    - Filter SLOs by service attributes
    - See basic SLO information including creation time and operation names

    Returns a formatted list showing:
    - SLO name and ARN
    - Associated service key attributes
    - Operation name being monitored
    - Creation timestamp
    - Total count of SLOs found

    This tool is useful for:
    - SLO discovery and inventory
    - Finding SLO names to use with get_slo() or audit_service_health()
    - Understanding what operations are being monitored
    """
    start_time_perf = timer()
    logger.debug('Starting list_slos request')

    try:
        # Parse key_attributes JSON string
        try:
            key_attrs_dict = json.loads(key_attributes) if key_attributes else {}
        except json.JSONDecodeError as e:
            return f'Error: Invalid JSON in key_attributes parameter: {str(e)}'

        # Validate max_results
        max_results = min(max(max_results, 1), 100)  # Ensure between 1 and 100

        # Build request parameters
        request_params = {
            'MaxResults': max_results,
            'IncludeLinkedAccounts': include_linked_accounts
        }

        # Add key attributes if provided
        if key_attrs_dict:
            request_params['KeyAttributes'] = key_attrs_dict

        logger.debug(f'Listing SLOs with parameters: {request_params}')

        # Call the Application Signals API
        response = appsignals_client.list_service_level_objectives(**request_params)
        slo_summaries = response.get('SloSummaries', [])

        logger.debug(f'Retrieved {len(slo_summaries)} SLO summaries')

        if not slo_summaries:
            logger.info('No SLOs found matching the criteria')
            return 'No Service Level Objectives found matching the specified criteria.'

        # Build formatted response
        result = f'Service Level Objectives ({len(slo_summaries)} total):\n\n'

        for slo in slo_summaries:
            slo_name = slo.get('Name', 'Unknown')
            slo_arn = slo.get('Arn', 'Unknown')
            operation_name = slo.get('OperationName', 'N/A')
            created_time = slo.get('CreatedTime', 'Unknown')

            result += f'• SLO: {slo_name}\n'
            result += f'  ARN: {slo_arn}\n'
            result += f'  Operation: {operation_name}\n'
            result += f'  Created: {created_time}\n'

            # Add key attributes if available
            key_attrs = slo.get('KeyAttributes', {})
            if key_attrs:
                result += '  Service Attributes:\n'
                for key, value in key_attrs.items():
                    result += f'    {key}: {value}\n'

            result += '\n'

        # Add pagination info if there might be more results
        next_token = response.get('NextToken')
        if next_token:
            result += f'Note: More SLOs may be available. This response shows the first {len(slo_summaries)} results.\n'

        elapsed_time = timer() - start_time_perf
        logger.debug(f'list_slos completed in {elapsed_time:.3f}s - found {len(slo_summaries)} SLOs')
        return result

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', 'Unknown error')
        logger.error(f'AWS ClientError in list_slos: {error_code} - {error_message}')
        return f'AWS Error: {error_message}'
    except Exception as e:
        logger.error(f'Unexpected error in list_slos: {str(e)}', exc_info=True)
        return f'Error: {str(e)}'


def main():
    """Run the MCP server."""
    logger.debug('Starting CloudWatch AppSignals MCP server')
    try:
        mcp.run(transport='stdio')
    except KeyboardInterrupt:
        logger.debug('Server shutdown by user')
    except Exception as e:
        logger.error(f'Server error: {e}', exc_info=True)
        raise


if __name__ == '__main__':
    main()
