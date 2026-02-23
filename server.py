#!/usr/bin/env python3
"""Steampipe AWS MCP Server — query AWS infrastructure via Steampipe."""

import json
import subprocess
import time
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("steampipe-aws", instructions=(
    "This server queries AWS infrastructure through Steampipe. "
    "Use list_tables to discover available tables, describe_table to see columns, "
    "and query_aws to run SQL queries against AWS resources."
))

STEAMPIPE_CMD = "steampipe"
DEFAULT_TIMEOUT = 30


def _run_steampipe_query(sql: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Execute a Steampipe SQL query and return parsed JSON result."""
    try:
        result = subprocess.run(
            [STEAMPIPE_CMD, "query", "--output", "json", sql],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Query timed out after {timeout} seconds")
    except FileNotFoundError:
        raise RuntimeError("Steampipe CLI not found. Ensure it is installed and on PATH.")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(f"Steampipe error: {stderr}")

    if not result.stdout.strip():
        return {"columns": [], "rows": []}

    return json.loads(result.stdout)


def _format_rows(data: dict, max_rows: int | None = None) -> str:
    """Format Steampipe JSON output into a readable text table."""
    rows = data.get("rows", [])
    if not rows:
        return "No results."

    if max_rows and len(rows) > max_rows:
        rows = rows[:max_rows]
        truncated = True
    else:
        truncated = False

    columns = [c["name"] for c in data.get("columns", [])]
    if not columns:
        columns = list(rows[0].keys())

    col_widths = {c: len(c) for c in columns}
    for row in rows:
        for c in columns:
            val = str(row.get(c, ""))
            col_widths[c] = max(col_widths[c], min(len(val), 60))

    header = " | ".join(c.ljust(col_widths[c]) for c in columns)
    separator = "-+-".join("-" * col_widths[c] for c in columns)

    lines = [header, separator]
    for row in rows:
        vals = []
        for c in columns:
            val = str(row.get(c, ""))
            if len(val) > 60:
                val = val[:57] + "..."
            vals.append(val.ljust(col_widths[c]))
        lines.append(" | ".join(vals))

    result = "\n".join(lines)
    result += f"\n\n({len(rows)} row{'s' if len(rows) != 1 else ''})"
    if truncated:
        result += f" — truncated to {max_rows}"
    return result


@mcp.tool()
def query_aws(sql: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Execute a Steampipe SQL query against AWS infrastructure.

    Args:
        sql: SQL query to run (e.g. "select instance_id, instance_type from aws_ec2_instance")
        timeout: Query timeout in seconds (default 30)
    """
    try:
        data = _run_steampipe_query(sql, timeout=timeout)
        return _format_rows(data)
    except RuntimeError as e:
        return f"Error: {e}"
    except json.JSONDecodeError as e:
        return f"Error parsing Steampipe output: {e}"


@mcp.tool()
def list_tables(keyword: str = "") -> str:
    """List available Steampipe AWS tables, optionally filtered by keyword.

    Args:
        keyword: Optional keyword to filter table names (e.g. "ec2", "s3", "iam")
    """
    sql = (
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = 'aws' ORDER BY table_name"
    )
    try:
        data = _run_steampipe_query(sql)
        tables = [r["table_name"] for r in data.get("rows", [])]

        if keyword:
            kw = keyword.lower()
            tables = [t for t in tables if kw in t.lower()]

        if not tables:
            return f"No tables found matching '{keyword}'." if keyword else "No tables found."

        result = f"Found {len(tables)} table{'s' if len(tables) != 1 else ''}"
        if keyword:
            result += f" matching '{keyword}'"
        result += ":\n\n" + "\n".join(tables)
        return result
    except RuntimeError as e:
        return f"Error: {e}"


@mcp.tool()
def describe_table(table_name: str) -> str:
    """Describe the columns of a Steampipe AWS table.

    Args:
        table_name: Full table name (e.g. "aws_ec2_instance")
    """
    sql = (
        f"SELECT column_name, data_type, is_nullable "
        f"FROM information_schema.columns "
        f"WHERE table_schema = 'aws' AND table_name = '{table_name}' "
        f"ORDER BY ordinal_position"
    )
    try:
        data = _run_steampipe_query(sql)
        rows = data.get("rows", [])

        if not rows:
            return f"Table '{table_name}' not found. Use list_tables to see available tables."

        lines = [f"Table: {table_name}", f"Columns ({len(rows)}):", ""]
        lines.append(f"{'Column':<40} {'Type':<20} {'Nullable'}")
        lines.append(f"{'-'*40} {'-'*20} {'-'*8}")
        for r in rows:
            lines.append(
                f"{r['column_name']:<40} {r['data_type']:<20} {r['is_nullable']}"
            )
        return "\n".join(lines)
    except RuntimeError as e:
        return f"Error: {e}"


_SUMMARY_QUERIES = [
    # ── Compute ──
    (
        "EC2 Instances",
        "SELECT instance_id, instance_state, instance_type, region "
        "FROM aws_ec2_instance ORDER BY instance_state, region",
    ),
    (
        "Auto Scaling Groups",
        "SELECT name, min_size, max_size, desired_capacity, region "
        "FROM aws_ec2_autoscaling_group ORDER BY name",
    ),
    (
        "ECS Clusters",
        "SELECT cluster_name, status, active_services_count, "
        "running_tasks_count, region "
        "FROM aws_ecs_cluster ORDER BY cluster_name",
    ),
    (
        "EKS Clusters",
        "SELECT name, status, version, region "
        "FROM aws_eks_cluster ORDER BY name",
    ),
    (
        "Lambda Functions",
        "SELECT name, runtime, memory_size, region "
        "FROM aws_lambda_function ORDER BY name",
    ),
    # ── Storage ──
    (
        "S3 Buckets",
        "SELECT name, region, versioning_enabled "
        "FROM aws_s3_bucket ORDER BY name",
    ),
    (
        "EBS Volumes",
        "SELECT volume_id, volume_type, size, state, region "
        "FROM aws_ebs_volume ORDER BY state, region",
    ),
    (
        "EFS File Systems",
        "SELECT file_system_id, life_cycle_state, size_in_bytes, region "
        "FROM aws_efs_file_system ORDER BY file_system_id",
    ),
    # ── Database / Cache ──
    (
        "RDS Instances",
        "SELECT db_instance_identifier, engine, class, status "
        "FROM aws_rds_db_instance ORDER BY status",
    ),
    (
        "DynamoDB Tables",
        "SELECT name, table_status, item_count, table_size_bytes, region "
        "FROM aws_dynamodb_table ORDER BY name",
    ),
    (
        "ElastiCache Clusters",
        "SELECT cache_cluster_id, engine, cache_node_type, "
        "cache_cluster_status, region "
        "FROM aws_elasticache_cluster ORDER BY cache_cluster_id",
    ),
    (
        "Redshift Clusters",
        "SELECT cluster_identifier, node_type, number_of_nodes, "
        "cluster_status, region "
        "FROM aws_redshift_cluster ORDER BY cluster_identifier",
    ),
    # ── Networking ──
    (
        "VPCs",
        "SELECT vpc_id, cidr_block, is_default, state, region "
        "FROM aws_vpc ORDER BY region",
    ),
    (
        "Subnets",
        "SELECT subnet_id, vpc_id, cidr_block, availability_zone, "
        "map_public_ip_on_launch "
        "FROM aws_vpc_subnet ORDER BY vpc_id, availability_zone",
    ),
    (
        "Security Groups",
        "SELECT group_id, group_name, vpc_id, region "
        "FROM aws_vpc_security_group ORDER BY vpc_id, group_name",
    ),
    (
        "NAT Gateways",
        "SELECT nat_gateway_id, state, vpc_id, subnet_id, region "
        "FROM aws_vpc_nat_gateway ORDER BY state",
    ),
    (
        "Internet Gateways",
        "SELECT internet_gateway_id, region "
        "FROM aws_vpc_internet_gateway ORDER BY region",
    ),
    (
        "Load Balancers (ALB/NLB/GLB)",
        "SELECT name, type, scheme, state_code, region "
        "FROM aws_ec2_application_load_balancer "
        "UNION ALL "
        "SELECT name, type, scheme, state_code, region "
        "FROM aws_ec2_network_load_balancer "
        "UNION ALL "
        "SELECT name, type, scheme, state_code, region "
        "FROM aws_ec2_gateway_load_balancer "
        "ORDER BY name",
    ),
    (
        "CloudFront Distributions",
        "SELECT id, domain_name, status, enabled "
        "FROM aws_cloudfront_distribution ORDER BY domain_name",
    ),
    (
        "Route 53 Hosted Zones",
        "SELECT name, resource_record_set_count, private_zone "
        "FROM aws_route53_zone ORDER BY name",
    ),
    # ── Security / Governance ──
    (
        "IAM Users",
        "SELECT name, create_date, mfa_enabled "
        "FROM aws_iam_user ORDER BY name",
    ),
    (
        "IAM Roles",
        "SELECT name, create_date, max_session_duration "
        "FROM aws_iam_role WHERE path = '/' ORDER BY name",
    ),
    (
        "KMS Keys",
        "SELECT id, region "
        "FROM aws_kms_key ORDER BY region",
    ),
    (
        "Secrets Manager Secrets",
        "SELECT name, created_date, region "
        "FROM aws_secretsmanager_secret ORDER BY name",
    ),
    (
        "CloudTrail Trails",
        "SELECT name, is_multi_region_trail, is_logging, region "
        "FROM aws_cloudtrail_trail ORDER BY name",
    ),
    # ── Messaging / Monitoring ──
    (
        "SNS Topics",
        "SELECT title, region "
        "FROM aws_sns_topic ORDER BY title",
    ),
    (
        "SQS Queues",
        "SELECT title, fifo_queue, region "
        "FROM aws_sqs_queue ORDER BY title",
    ),
    (
        "CloudWatch Alarms",
        "SELECT name, state_value, metric_name, namespace, region "
        "FROM aws_cloudwatch_alarm ORDER BY state_value, name",
    ),
]


@mcp.tool()
def get_aws_summary() -> str:
    """Generate a comprehensive summary report of AWS infrastructure.

    Covers: EC2, ASG, ECS, EKS, Lambda, S3, EBS, EFS, RDS, DynamoDB,
    ElastiCache, Redshift, VPC, Subnets, Security Groups, NAT/Internet
    Gateways, Load Balancers, CloudFront, Route 53, IAM Users/Roles,
    KMS, Secrets Manager, CloudTrail, SNS, SQS, CloudWatch Alarms.

    Queries run sequentially for Steampipe service stability.
    """
    sections = []

    for title, sql in _SUMMARY_QUERIES:
        try:
            data = _run_steampipe_query(sql, timeout=DEFAULT_TIMEOUT)
            rows = data.get("rows", [])
            body = _format_rows(data, max_rows=50) if rows else "None found."
            sections.append(f"## {title} ({len(rows)})\n\n{body}")
        except RuntimeError as e:
            sections.append(f"## {title}\n\nError: {e}")

    return "# AWS Infrastructure Summary\n\n" + "\n\n---\n\n".join(sections)


# ─── Report data cache ────────────────────────────────────────────────
_report_cache: dict = {}          # title -> {"rows": [...], "columns": [...]}
_report_cache_time: float = 0.0   # epoch seconds
_CACHE_TTL = 300                  # 5 min


def _collect_all_data() -> dict[str, dict]:
    """Run all summary queries and cache results. Returns {title: data}."""
    global _report_cache, _report_cache_time
    if _report_cache and (time.time() - _report_cache_time < _CACHE_TTL):
        return _report_cache

    result = {}
    for title, sql in _SUMMARY_QUERIES:
        try:
            result[title] = _run_steampipe_query(sql, timeout=DEFAULT_TIMEOUT)
        except RuntimeError as e:
            result[title] = {"columns": [], "rows": [], "error": str(e)}
    _report_cache = result
    _report_cache_time = time.time()
    return result


def _summarize_data(data: dict[str, dict]) -> str:
    """Produce a compact statistical summary for AI analysis."""
    lines = []

    def rows(title: str) -> list[dict]:
        return data.get(title, {}).get("rows", [])

    def count(title: str) -> int:
        return len(rows(title))

    # ── Compute ──
    ec2 = rows("EC2 Instances")
    running = [r for r in ec2 if r.get("instance_state") == "running"]
    stopped = [r for r in ec2 if r.get("instance_state") == "stopped"]
    types = {}
    for r in ec2:
        t = r.get("instance_type", "?")
        types[t] = types.get(t, 0) + 1
    lines.append(f"[Compute]")
    lines.append(f"  EC2: {len(ec2)} total ({len(running)} running, {len(stopped)} stopped) | types: {types}")
    lines.append(f"  ASG: {count('Auto Scaling Groups')} | ECS Clusters: {count('ECS Clusters')} | EKS Clusters: {count('EKS Clusters')}")
    lam = rows("Lambda Functions")
    runtimes = {}
    for r in lam:
        rt = r.get("runtime", "?")
        runtimes[rt] = runtimes.get(rt, 0) + 1
    lines.append(f"  Lambda: {len(lam)} functions | runtimes: {runtimes}")

    # ── Storage ──
    s3 = rows("S3 Buckets")
    versioned = sum(1 for r in s3 if str(r.get("versioning_enabled", "")).lower() == "true")
    lines.append(f"[Storage]")
    lines.append(f"  S3: {len(s3)} buckets ({versioned} versioned, {len(s3)-versioned} not)")
    ebs = rows("EBS Volumes")
    available_ebs = [r for r in ebs if r.get("state") == "available"]
    total_ebs_gb = sum(int(r.get("size", 0)) for r in ebs)
    avail_ebs_gb = sum(int(r.get("size", 0)) for r in available_ebs)
    lines.append(f"  EBS: {len(ebs)} volumes ({total_ebs_gb} GB total, {len(available_ebs)} unattached = {avail_ebs_gb} GB wasted)")
    lines.append(f"  EFS: {count('EFS File Systems')} file systems")

    # ── Database ──
    lines.append(f"[Database/Cache]")
    lines.append(f"  RDS: {count('RDS Instances')} | DynamoDB: {count('DynamoDB Tables')} | ElastiCache: {count('ElastiCache Clusters')} | Redshift: {count('Redshift Clusters')}")

    # ── Networking ──
    vpcs = rows("VPCs")
    subnets = rows("Subnets")
    pub_subnets = [s for s in subnets if str(s.get("map_public_ip_on_launch", "")).lower() == "true"]
    sgs = rows("Security Groups")
    lines.append(f"[Networking]")
    lines.append(f"  VPCs: {len(vpcs)} | Subnets: {len(subnets)} ({len(pub_subnets)} public, {len(subnets)-len(pub_subnets)} private)")
    lines.append(f"  Security Groups: {len(sgs)} | NAT GWs: {count('NAT Gateways')} | IGWs: {count('Internet Gateways')}")
    lines.append(f"  Load Balancers: {count('Load Balancers (ALB/NLB/GLB)')} | CloudFront: {count('CloudFront Distributions')}")
    r53 = rows("Route 53 Hosted Zones")
    lines.append(f"  Route 53: {len(r53)} zones ({sum(1 for z in r53 if str(z.get('private_zone','')).lower()=='true')} private)")

    # ── Security ──
    iam_users = rows("IAM Users")
    no_mfa = [u for u in iam_users if str(u.get("mfa_enabled", "")).lower() != "true"]
    trails = rows("CloudTrail Trails")
    logging_trails = [t for t in trails if str(t.get("is_logging", "")).lower() == "true"]
    lines.append(f"[Security/Governance]")
    lines.append(f"  IAM Users: {len(iam_users)} ({len(no_mfa)} without MFA)")
    lines.append(f"  IAM Roles: {count('IAM Roles')} | KMS Keys: {count('KMS Keys')}")
    lines.append(f"  Secrets Manager: {count('Secrets Manager Secrets')} secrets")
    lines.append(f"  CloudTrail: {len(trails)} trails ({len(logging_trails)} actively logging)")

    # ── Monitoring ──
    alarms = rows("CloudWatch Alarms")
    alarm_states = {}
    for a in alarms:
        st = a.get("state_value", "?")
        alarm_states[st] = alarm_states.get(st, 0) + 1
    lines.append(f"[Messaging/Monitoring]")
    lines.append(f"  SNS: {count('SNS Topics')} topics | SQS: {count('SQS Queues')} queues")
    lines.append(f"  CloudWatch Alarms: {len(alarms)} | states: {alarm_states}")

    return "\n".join(lines)


_REPORT_SECTIONS = [
    "executive_summary",
    "compute_analysis",
    "storage_analysis",
    "database_analysis",
    "networking_analysis",
    "security_analysis",
    "monitoring_analysis",
    "compliance_analysis",
    "recommendations",
]


@mcp.tool()
def get_report_data() -> str:
    """Collect all AWS resource data and return a compact statistical summary.

    Call this FIRST, then use the returned summary to write analysis.
    Pass the analysis to generate_html_report() to produce the final HTML.

    The summary is intentionally compact (key counts and breakdowns only)
    so you can focus on writing insightful analysis without wasting tokens
    on raw data formatting.
    """
    data = _collect_all_data()
    errors = [t for t, d in data.items() if d.get("error")]
    summary = _summarize_data(data)

    header = (
        f"AWS Account: 977099011692 | Region: ap-northeast-2\n"
        f"Collected: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"Sections queried: {len(data)} | Errors: {len(errors)}"
    )
    if errors:
        header += f"\nFailed sections: {', '.join(errors)}"

    instructions = (
        "\n--- INSTRUCTIONS ---\n"
        "Based on the summary above, write analysis for these sections:\n"
        "  1. executive_summary     — 2-3 sentence overview of the infrastructure\n"
        "  2. compute_analysis      — EC2, Lambda, containers assessment\n"
        "  3. storage_analysis      — S3 versioning, EBS waste, etc.\n"
        "  4. database_analysis     — DB and cache layer observations\n"
        "  5. networking_analysis   — VPC design, SG sprawl, LB setup\n"
        "  6. security_analysis     — IAM hygiene, MFA, encryption, logging\n"
        "  7. monitoring_analysis   — Alarms, alerting coverage\n"
        "  8. compliance_analysis   — Security compliance check summary\n"
        "  9. recommendations       — Top 3-5 actionable items\n"
        "\nThen call generate_html_report with your analysis."
    )

    return header + "\n\n" + summary + instructions


# ─── Extended AWS Foundational Security Controls ──────────────────────
_EXTENDED_SECURITY_CHECKS = [
    # Lambda Controls (현재 환경: 6개 함수)
    {
        "id": "foundational_security_lambda_1",
        "title": "[Lambda.1] Lambda function policies should prohibit public access",
        "description": "Checks whether Lambda function resource-based policy prohibits public access outside of your account",
        "severity": "CRITICAL",
        "query": """
        SELECT
          name,
          arn,
          region,
          policy_std::text as policy
        FROM aws_lambda_function
        WHERE policy_std::text LIKE '%"Principal":"*"%'
           OR policy_std::text LIKE '%"Principal":{"AWS":"*"}%'
        ORDER BY name
        """
    },
    {
        "id": "foundational_security_lambda_2",
        "title": "[Lambda.2] Lambda functions should use supported runtimes",
        "description": "Checks that Lambda function runtimes match expected values for latest supported runtimes",
        "severity": "MEDIUM",
        "query": """
        SELECT
          name,
          runtime,
          region,
          last_modified
        FROM aws_lambda_function
        WHERE runtime NOT IN (
          'nodejs20.x', 'nodejs18.x', 'python3.12', 'python3.11', 'python3.10', 'python3.9',
          'ruby3.3', 'ruby3.2', 'java21', 'java17', 'java11', 'java8.al2', 'dotnet8', 'dotnet6'
        )
        ORDER BY name
        """
    },
    # DynamoDB Controls (현재 환경: 7개 테이블)
    {
        "id": "foundational_security_dynamodb_1",
        "title": "[DynamoDB.1] DynamoDB tables should automatically scale capacity with demand",
        "description": "Checks whether DynamoDB tables can scale capacity up or down based on demand",
        "severity": "MEDIUM",
        "query": """
        SELECT
          name,
          billing_mode,
          region
        FROM aws_dynamodb_table
        WHERE billing_mode = 'PROVISIONED'
        ORDER BY name
        """
    },
    {
        "id": "foundational_security_dynamodb_2",
        "title": "[DynamoDB.2] DynamoDB tables should have point-in-time recovery enabled",
        "description": "Checks whether point-in-time recovery is enabled for DynamoDB tables",
        "severity": "MEDIUM",
        "query": """
        SELECT
          name,
          point_in_time_recovery_enabled,
          region
        FROM aws_dynamodb_table
        WHERE point_in_time_recovery_enabled = false
        ORDER BY name
        """
    },
    {
        "id": "foundational_security_dynamodb_3",
        "title": "[DynamoDB.3] DynamoDB Accelerator (DAX) clusters should be encrypted at rest",
        "description": "Checks whether DAX clusters are encrypted at rest",
        "severity": "MEDIUM",
        "query": """
        SELECT
          cluster_name,
          sse_description,
          region
        FROM aws_dax_cluster
        WHERE sse_description IS NULL
        ORDER BY cluster_name
        """
    },
    # SNS Controls (현재 환경: 2개 토픽)
    {
        "id": "foundational_security_sns_1",
        "title": "[SNS.1] SNS topics should be encrypted at rest using AWS KMS",
        "description": "Checks whether SNS topics are encrypted at rest using AWS KMS",
        "severity": "MEDIUM",
        "query": """
        SELECT
          title,
          kms_master_key_id,
          region
        FROM aws_sns_topic
        WHERE kms_master_key_id IS NULL
        ORDER BY title
        """
    },
    {
        "id": "foundational_security_sns_2",
        "title": "[SNS.2] Delivery status logging should be enabled for notification messages sent to a platform endpoint",
        "description": "Checks whether delivery status logging is enabled for SNS topic platform endpoints",
        "severity": "MEDIUM",
        "query": """
        SELECT
          title,
          application_success_feedback_role_arn,
          application_failure_feedback_role_arn,
          region
        FROM aws_sns_topic
        WHERE application_success_feedback_role_arn IS NULL
           OR application_failure_feedback_role_arn IS NULL
        ORDER BY title
        """
    },
    # RDS Controls (미래 확장용)
    {
        "id": "foundational_security_rds_1",
        "title": "[RDS.1] RDS snapshots should be private",
        "description": "Checks whether Amazon RDS snapshots are public",
        "severity": "CRITICAL",
        "query": """
        SELECT
          db_snapshot_identifier,
          db_instance_identifier,
          snapshot_type,
          region
        FROM aws_rds_db_snapshot
        WHERE jsonb_array_length(db_snapshot_attributes) > 0
        ORDER BY db_snapshot_identifier
        """
    },
    {
        "id": "foundational_security_rds_2",
        "title": "[RDS.2] RDS DB instances should prohibit public access",
        "description": "Checks whether RDS instances are publicly accessible by evaluating PubliclyAccessible configuration",
        "severity": "CRITICAL",
        "query": """
        SELECT
          db_instance_identifier,
          publicly_accessible,
          engine,
          region
        FROM aws_rds_db_instance
        WHERE publicly_accessible = true
        ORDER BY db_instance_identifier
        """
    },
    # Secrets Manager Controls (현재 환경: 7개 시크릿)
    {
        "id": "foundational_security_secretsmanager_1",
        "title": "[SecretsManager.1] Secrets Manager secrets should have automatic rotation enabled",
        "description": "Checks whether Secrets Manager secrets have rotation enabled",
        "severity": "MEDIUM",
        "query": """
        SELECT
          name,
          rotation_enabled,
          rotation_lambda_arn,
          region
        FROM aws_secretsmanager_secret
        WHERE rotation_enabled = false
        ORDER BY name
        """
    },
    {
        "id": "foundational_security_secretsmanager_2",
        "title": "[SecretsManager.2] Secrets Manager secrets configured with automatic rotation should rotate successfully",
        "description": "Checks whether Secrets Manager secrets rotated successfully based on rotation configuration",
        "severity": "MEDIUM",
        "query": """
        SELECT
          name,
          rotation_enabled,
          last_rotated_date,
          region
        FROM aws_secretsmanager_secret
        WHERE rotation_enabled = true
          AND (last_rotated_date IS NULL OR last_rotated_date < NOW() - INTERVAL '90 days')
        ORDER BY name
        """
    },
    # Route53 Controls (현재 환경: 6개 호스팅 존)
    {
        "id": "foundational_security_route53_2",
        "title": "[Route53.2] Route 53 public hosted zones should log DNS queries",
        "description": "Checks whether Route 53 public hosted zones are logging DNS queries to CloudWatch Logs",
        "severity": "MEDIUM",
        "query": """
        SELECT
          name,
          private_zone,
          query_logging_configs,
          region
        FROM aws_route53_zone
        WHERE private_zone = false
          AND (query_logging_configs IS NULL OR jsonb_array_length(query_logging_configs) = 0)
        ORDER BY name
        """
    },
]


@mcp.tool()
def run_all_foundational_security_checks() -> str:
    """Run comprehensive AWS Foundational Security Best Practices compliance checks.

    Executes both basic (8 controls) and extended (12 additional controls) security checks
    covering Lambda, DynamoDB, SNS, RDS, Secrets Manager, and Route 53 services.

    Total: 20 AWS Foundational Security controls out of 339 available.
    This covers the most critical security controls for common AWS services.
    """
    all_checks = _SECURITY_CHECKS + _EXTENDED_SECURITY_CHECKS

    results = []
    results.append(f"# Comprehensive AWS Foundational Security Report")
    results.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    results.append(f"Controls executed: {len(all_checks)} / 339 total available")
    results.append(f"Coverage: {len(all_checks)/339*100:.1f}% of AWS Foundational Security Best Practices")
    results.append("")

    total_issues = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    service_counts = {}

    for check in all_checks:
        service = check["id"].split("_")[2]  # Extract service from ID
        service_counts[service] = service_counts.get(service, 0) + 1

        results.append(f"## {check['title']} ({check['severity']})")
        results.append(f"**Service**: {service.upper()}")
        results.append(f"**Description**: {check['description']}")
        results.append("")

        try:
            data = _run_steampipe_query(check["query"], timeout=DEFAULT_TIMEOUT)
            rows = data.get("rows", [])

            if rows:
                results.append(f"**❌ FAILED**: {len(rows)} issue(s) found")
                results.append("")
                results.append(_format_rows(data, max_rows=25))
                total_issues += len(rows)
                severity_counts[check["severity"]] += len(rows)
            else:
                results.append(f"**✅ PASSED**: No issues found")

        except RuntimeError as e:
            results.append(f"**⚠️ ERROR**: {e}")

        results.append("")
        results.append("---")
        results.append("")

    # Summary
    summary_lines = [
        f"## Executive Summary",
        f"",
        f"**Total Security Issues**: {total_issues}",
        f"- Critical Severity: {severity_counts['CRITICAL']}",
        f"- High Severity: {severity_counts['HIGH']}",
        f"- Medium Severity: {severity_counts['MEDIUM']}",
        f"- Low Severity: {severity_counts['LOW']}",
        f"",
        f"**Services Scanned**: {len(service_counts)}",
    ]
    for service, count in sorted(service_counts.items()):
        summary_lines.append(f"- {service.upper()}: {count} controls")
    summary_lines.append("")

    # Insert summary after header
    header_end = 5  # After coverage line
    results[header_end:header_end] = summary_lines

    return "\n".join(results)


def _html_table(d: dict, max_rows: int = 50) -> str:
    """Convert Steampipe query result dict to an HTML <table>."""
    rows = d.get("rows", [])
    cols = [c["name"] for c in d.get("columns", [])]
    if not cols and rows:
        cols = list(rows[0].keys())
    if not rows:
        return '<p class="empty">No resources found.</p>'

    truncated = len(rows) > max_rows
    display_rows = rows[:max_rows]

    parts = ['<table><thead><tr>']
    for c in cols:
        parts.append(f'<th>{escape(c)}</th>')
    parts.append('</tr></thead><tbody>')
    for row in display_rows:
        parts.append('<tr>')
        for c in cols:
            val = str(row.get(c, ""))
            parts.append(f'<td>{escape(val)}</td>')
        parts.append('</tr>')
    parts.append('</tbody></table>')
    parts.append(f'<p class="row-count">{len(rows)} row{"s" if len(rows)!=1 else ""}'
                 + (f' (showing first {max_rows})' if truncated else '')
                 + '</p>')
    return "\n".join(parts)


_SECTION_LABELS = {
    "executive_summary": "Executive Summary",
    "compute_analysis": "Compute",
    "storage_analysis": "Storage",
    "database_analysis": "Database & Cache",
    "networking_analysis": "Networking",
    "security_analysis": "Security & Governance",
    "monitoring_analysis": "Messaging & Monitoring",
    "compliance_analysis": "Security Compliance",
    "recommendations": "Recommendations",
}

_SECTION_DATA_MAP: dict[str, list[str]] = {
    "compute_analysis": [
        "EC2 Instances", "Auto Scaling Groups", "ECS Clusters",
        "EKS Clusters", "Lambda Functions",
    ],
    "storage_analysis": ["S3 Buckets", "EBS Volumes", "EFS File Systems"],
    "database_analysis": [
        "RDS Instances", "DynamoDB Tables",
        "ElastiCache Clusters", "Redshift Clusters",
    ],
    "networking_analysis": [
        "VPCs", "Subnets", "Security Groups", "NAT Gateways",
        "Internet Gateways", "Load Balancers (ALB/NLB/GLB)",
        "CloudFront Distributions", "Route 53 Hosted Zones",
    ],
    "security_analysis": [
        "IAM Users", "IAM Roles", "KMS Keys",
        "Secrets Manager Secrets", "CloudTrail Trails",
    ],
    "monitoring_analysis": [
        "SNS Topics", "SQS Queues", "CloudWatch Alarms",
    ],
}


_CSS = """\
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: 'Segoe UI',system-ui,-apple-system,sans-serif;
       color:#1a1a2e; background:#f0f2f5; padding:24px; line-height:1.5; }
.container { max-width:1200px; margin:0 auto; }
header { background:linear-gradient(135deg,#232f3e 0%,#37475a 100%);
         color:#fff; padding:32px 40px; border-radius:12px; margin-bottom:28px; }
header h1 { font-size:26px; font-weight:700; }
header .meta { font-size:13px; color:#a0b4c8; margin-top:6px; }
/* Dashboard cards */
.dashboard { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr));
             gap:14px; margin-bottom:28px; }
.card { background:#fff; border-radius:10px; padding:18px 20px;
        box-shadow:0 1px 3px rgba(0,0,0,.08); text-align:center; }
.card .num { font-size:28px; font-weight:700; color:#232f3e; }
.card .label { font-size:12px; color:#666; margin-top:2px; text-transform:uppercase;
               letter-spacing:.5px; }
/* Sections */
.section { background:#fff; border-radius:10px; padding:28px 32px;
           box-shadow:0 1px 3px rgba(0,0,0,.08); margin-bottom:20px; }
.section h2 { font-size:20px; color:#232f3e; margin-bottom:16px;
              border-bottom:2px solid #ff9900; padding-bottom:8px; display:inline-block; }
.ai-box { background:#fef9ec; border-left:4px solid #ff9900;
          padding:16px 20px; border-radius:0 8px 8px 0;
          margin-bottom:20px; font-size:14px; white-space:pre-wrap; }
.ai-box strong { color:#b8860b; }
table { width:100%; border-collapse:collapse; font-size:13px; margin-top:10px; }
th { background:#f7f8fa; text-align:left; padding:8px 10px; font-weight:600;
     color:#555; border-bottom:2px solid #e0e0e0; white-space:nowrap; }
td { padding:7px 10px; border-bottom:1px solid #eee; }
tr:hover td { background:#fafbfd; }
.empty { color:#888; font-style:italic; padding:12px 0; }
.row-count { font-size:12px; color:#888; margin-top:6px; }
/* Recommendations */
.reco-box { background:#eef6ee; border-left:4px solid #2e7d32;
            padding:16px 20px; border-radius:0 8px 8px 0;
            font-size:14px; white-space:pre-wrap; }
.reco-box strong { color:#2e7d32; }
footer { text-align:center; color:#999; font-size:12px; margin-top:32px; }
@media print { body { background:#fff; padding:0; }
               .section { box-shadow:none; break-inside:avoid; } }
"""


@mcp.tool()
def generate_html_report(
    executive_summary: str,
    compute_analysis: str,
    storage_analysis: str,
    database_analysis: str,
    networking_analysis: str,
    security_analysis: str,
    monitoring_analysis: str,
    compliance_analysis: str,
    recommendations: str,
) -> str:
    """Generate a full HTML infrastructure report.

    Call get_report_data() first to obtain the statistical summary, write
    your analysis for each section, then pass them here.

    The HTML is built from:
      - Static template (layout, CSS) — no tokens spent
      - Data tables — filled directly from cached Steampipe results
      - Your analysis text — inserted into highlighted boxes

    Args:
        executive_summary: 2-3 sentence infrastructure overview
        compute_analysis: EC2, Lambda, ECS/EKS assessment
        storage_analysis: S3, EBS, EFS observations
        database_analysis: RDS, DynamoDB, cache observations
        networking_analysis: VPC design, SG, LB assessment
        security_analysis: IAM, MFA, encryption, logging assessment
        monitoring_analysis: CloudWatch, SNS, SQS assessment
        compliance_analysis: Security compliance check summary and analysis
        recommendations: Top 3-5 actionable recommendation items
    """
    analysis = {
        "executive_summary": executive_summary,
        "compute_analysis": compute_analysis,
        "storage_analysis": storage_analysis,
        "database_analysis": database_analysis,
        "networking_analysis": networking_analysis,
        "security_analysis": security_analysis,
        "monitoring_analysis": monitoring_analysis,
        "compliance_analysis": compliance_analysis,
        "recommendations": recommendations,
    }
    data = _collect_all_data()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Dashboard counts
    def cnt(title: str) -> int:
        return len(data.get(title, {}).get("rows", []))
    dashboard_items = [
        ("EC2", cnt("EC2 Instances")),
        ("Lambda", cnt("Lambda Functions")),
        ("S3", cnt("S3 Buckets")),
        ("EBS", cnt("EBS Volumes")),
        ("RDS", cnt("RDS Instances")),
        ("DynamoDB", cnt("DynamoDB Tables")),
        ("VPCs", cnt("VPCs")),
        ("Subnets", cnt("Subnets")),
        ("Security Groups", cnt("Security Groups")),
        ("IAM Users", cnt("IAM Users")),
        ("IAM Roles", cnt("IAM Roles")),
        ("Secrets", cnt("Secrets Manager Secrets")),
    ]
    dash_html = "\n".join(
        f'<div class="card"><div class="num">{n}</div><div class="label">{escape(lbl)}</div></div>'
        for lbl, n in dashboard_items
    )

    # Build sections
    sections_html = []

    # Executive summary (no data tables)
    sections_html.append(
        f'<div class="section"><h2>Executive Summary</h2>'
        f'<div class="ai-box"><strong>AI Analysis</strong>\n{escape(analysis["executive_summary"])}</div>'
        f'</div>'
    )

    # Data sections with tables + AI analysis
    for key in ["compute_analysis", "storage_analysis", "database_analysis",
                 "networking_analysis", "security_analysis", "monitoring_analysis"]:
        label = _SECTION_LABELS[key]
        titles = _SECTION_DATA_MAP.get(key, [])
        sec = f'<div class="section"><h2>{escape(label)}</h2>'
        sec += f'<div class="ai-box"><strong>AI Analysis</strong>\n{escape(analysis[key])}</div>'
        for t in titles:
            d = data.get(t, {"columns": [], "rows": []})
            sec += f'<h3 style="margin-top:18px;font-size:15px;color:#37475a;">{escape(t)} ({len(d.get("rows",[]))})</h3>'
            if d.get("error"):
                sec += f'<p class="empty">Error: {escape(d["error"])}</p>'
            else:
                sec += _html_table(d)
        sec += '</div>'
        sections_html.append(sec)

    # Compliance analysis (no data tables, just AI analysis)
    sections_html.append(
        f'<div class="section"><h2>{escape(_SECTION_LABELS["compliance_analysis"])}</h2>'
        f'<div class="ai-box"><strong>AI Analysis</strong>\n{escape(analysis["compliance_analysis"])}</div>'
        f'</div>'
    )

    # Recommendations
    sections_html.append(
        f'<div class="section"><h2>Recommendations</h2>'
        f'<div class="reco-box"><strong>AI Recommendations</strong>\n{escape(analysis["recommendations"])}</div>'
        f'</div>'
    )

    html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AWS Infrastructure Report — {now}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
<header>
  <h1>AWS Infrastructure Report</h1>
  <div class="meta">Account 977099011692 · ap-northeast-2 · Generated {now}</div>
</header>
<div class="dashboard">{dash_html}</div>
{"".join(sections_html)}
<footer>Generated by Steampipe AWS MCP Server · Data queried via Steampipe v2.3.5</footer>
</div>
</body>
</html>"""

    out_path = Path("/home/ec2-user/claude-code/mcp-test/report.html")
    out_path.write_text(html, encoding="utf-8")
    return f"Report saved to {out_path} ({len(html):,} bytes)"


# ─── AWS Foundational Security Best Practices ─────────────────────────
_SECURITY_CHECKS = [
    {
        "id": "foundational_security_iam_1",
        "title": "[IAM.1] IAM policies should not allow full '*' administrative privileges",
        "description": "Checks whether IAM customer managed policies have administrator access with 'Effect': 'Allow' with 'Action': '*' over 'Resource': '*'",
        "severity": "HIGH",
        "query": """
        SELECT
          policy_name,
          arn,
          create_date,
          attachment_count
        FROM aws_iam_policy
        WHERE is_aws_managed = false
          AND policy_document_std::text LIKE '%"Effect":"Allow"%'
          AND policy_document_std::text LIKE '%"Action":"*"%'
          AND policy_document_std::text LIKE '%"Resource":"*"%'
        ORDER BY policy_name
        """
    },
    {
        "id": "foundational_security_iam_5",
        "title": "[IAM.5] MFA should be enabled for all IAM users that have a console password",
        "description": "Checks whether AWS multi-factor authentication (MFA) is enabled for all IAM users that use a console password",
        "severity": "MEDIUM",
        "query": """
        SELECT
          name,
          create_date,
          password_last_used,
          mfa_enabled
        FROM aws_iam_user
        WHERE password_enabled = true
          AND mfa_enabled = false
        ORDER BY name
        """
    },
    {
        "id": "foundational_security_s3_1",
        "title": "[S3.1] S3 Block Public Access setting should be enabled",
        "description": "Checks whether S3 public access block settings are configured at the account level",
        "severity": "MEDIUM",
        "query": """
        SELECT
          name,
          region,
          block_public_acls,
          block_public_policy,
          ignore_public_acls,
          restrict_public_buckets
        FROM aws_s3_bucket
        WHERE block_public_acls = false
           OR block_public_policy = false
           OR ignore_public_acls = false
           OR restrict_public_buckets = false
        ORDER BY name
        """
    },
    {
        "id": "foundational_security_s3_2",
        "title": "[S3.2] S3 buckets should prohibit public read access",
        "description": "Checks whether your S3 buckets allow public read access by evaluating Block Public Access settings, bucket policy, and bucket ACL",
        "severity": "CRITICAL",
        "query": """
        SELECT
          name,
          region,
          bucket_policy_is_public,
          block_public_acls,
          block_public_policy
        FROM aws_s3_bucket
        WHERE bucket_policy_is_public = true
           OR block_public_acls = false
           OR block_public_policy = false
        ORDER BY name
        """
    },
    {
        "id": "foundational_security_ec2_2",
        "title": "[EC2.2] VPC default security groups should not allow inbound or outbound traffic",
        "description": "Checks that default security group of a VPC does not allow inbound or outbound traffic",
        "severity": "HIGH",
        "query": """
        SELECT
          group_id,
          group_name,
          vpc_id,
          region
        FROM aws_vpc_security_group
        WHERE group_name = 'default'
          AND (
            jsonb_array_length(ip_permissions) > 0
            OR jsonb_array_length(ip_permissions_egress) > 1
          )
        ORDER BY vpc_id
        """
    },
    {
        "id": "foundational_security_ec2_3",
        "title": "[EC2.3] Attached EBS volumes should be encrypted at rest",
        "description": "Checks whether EBS volumes that are in an attached state are encrypted",
        "severity": "MEDIUM",
        "query": """
        SELECT
          volume_id,
          volume_type,
          size,
          state,
          encrypted,
          region
        FROM aws_ebs_volume
        WHERE state = 'in-use'
          AND encrypted = false
        ORDER BY volume_id
        """
    },
    {
        "id": "foundational_security_cloudtrail_1",
        "title": "[CloudTrail.1] CloudTrail should be enabled and configured with at least one multi-Region trail",
        "description": "Checks that there is at least one multi-Region CloudTrail trail",
        "severity": "HIGH",
        "query": """
        WITH multi_region_trails AS (
          SELECT COUNT(*) as trail_count
          FROM aws_cloudtrail_trail
          WHERE is_multi_region_trail = true
            AND is_logging = true
        )
        SELECT
          name,
          region,
          is_logging,
          is_multi_region_trail,
          include_global_service_events
        FROM aws_cloudtrail_trail
        WHERE NOT EXISTS (
          SELECT 1 FROM multi_region_trails WHERE trail_count > 0
        )
        ORDER BY name
        """
    },
    {
        "id": "foundational_security_ec2_15",
        "title": "[EC2.15] EC2 subnets should not automatically assign public IP addresses",
        "description": "Checks whether EC2 subnets have automatic assignment of public IP addresses enabled",
        "severity": "MEDIUM",
        "query": """
        SELECT
          subnet_id,
          vpc_id,
          availability_zone,
          cidr_block,
          map_public_ip_on_launch
        FROM aws_vpc_subnet
        WHERE map_public_ip_on_launch = true
        ORDER BY vpc_id, subnet_id
        """
    },
]


@mcp.tool()
def run_security_checks(check_ids: str = "") -> str:
    """Run AWS Foundational Security Best Practices compliance checks.

    Performs security checks based on official AWS Security Hub Foundational Security
    standard. These are production-ready controls used by AWS Security Hub.

    Args:
        check_ids: Optional comma-separated list of check IDs to run.
                  If empty, runs all checks. Available AWS Foundational Security controls:
                  - foundational_security_iam_1: IAM policies with full admin privileges
                  - foundational_security_iam_5: IAM users without MFA
                  - foundational_security_s3_1: S3 Block Public Access not enabled
                  - foundational_security_s3_2: S3 buckets with public read access
                  - foundational_security_ec2_2: VPC default security groups with traffic
                  - foundational_security_ec2_3: Unencrypted attached EBS volumes
                  - foundational_security_cloudtrail_1: No multi-region CloudTrail
                  - foundational_security_ec2_15: Subnets auto-assign public IPs
    """
    if check_ids.strip():
        requested_ids = [cid.strip() for cid in check_ids.split(",")]
        checks_to_run = [c for c in _SECURITY_CHECKS if c["id"] in requested_ids]
        if not checks_to_run:
            return f"Error: No valid check IDs found in '{check_ids}'"
    else:
        checks_to_run = _SECURITY_CHECKS

    results = []
    results.append(f"# AWS Security Compliance Report")
    results.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    results.append(f"Checks run: {len(checks_to_run)}")
    results.append("")

    total_issues = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for check in checks_to_run:
        results.append(f"## {check['title']} ({check['severity']})")
        results.append(f"**Description**: {check['description']}")
        results.append("")

        try:
            data = _run_steampipe_query(check["query"], timeout=DEFAULT_TIMEOUT)
            rows = data.get("rows", [])

            if rows:
                results.append(f"**❌ FAILED**: {len(rows)} issue(s) found")
                results.append("")
                results.append(_format_rows(data, max_rows=25))
                total_issues += len(rows)
                severity_counts[check["severity"]] += len(rows)
            else:
                results.append(f"**✅ PASSED**: No issues found")

        except RuntimeError as e:
            results.append(f"**⚠️ ERROR**: {e}")

        results.append("")
        results.append("---")
        results.append("")

    # Summary
    summary_lines = [
        f"## Summary",
        f"",
        f"**Total Issues**: {total_issues}",
        f"- Critical Severity: {severity_counts['CRITICAL']}",
        f"- High Severity: {severity_counts['HIGH']}",
        f"- Medium Severity: {severity_counts['MEDIUM']}",
        f"- Low Severity: {severity_counts['LOW']}",
        f"",
    ]

    # Insert summary after header
    header_end = 4  # After "Generated:", "Checks run:", and empty line
    results[header_end:header_end] = summary_lines

    return "\n".join(results)


if __name__ == "__main__":
    mcp.run()
