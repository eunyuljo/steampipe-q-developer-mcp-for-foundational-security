"""AWS Foundational Security Best Practices checker."""

from datetime import datetime, timezone
from dataclasses import dataclass
from typing import List, Dict, Optional, Any
from steampipe_client import SteampipeClient, ResultFormatter


@dataclass
class SecurityControl:
    """AWS Foundational Security control definition."""
    id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    query: str
    service: Optional[str] = None

    def __post_init__(self):
        if self.service is None:
            # Extract service from ID (e.g., foundational_security_s3_1 -> s3)
            parts = self.id.split("_")
            if len(parts) >= 3:
                self.service = parts[2].upper()


@dataclass
class SecurityCheckResult:
    """Result of a security check."""
    control: SecurityControl
    passed: bool
    issue_count: int
    details: str


class SecurityChecker:
    """AWS Foundational Security Best Practices checker."""

    def __init__(self, steampipe_client: SteampipeClient):
        self.client = steampipe_client
        self.controls = self._load_controls()

    def run_checks(self, control_ids: Optional[List[str]] = None) -> List[SecurityCheckResult]:
        """Run security checks for specified controls or all controls."""
        if control_ids:
            controls_to_run = [c for c in self.controls if c.id in control_ids]
        else:
            controls_to_run = self.controls

        results = []
        for control in controls_to_run:
            result = self._run_single_check(control)
            results.append(result)

        return results

    def generate_report(self, results: List[SecurityCheckResult]) -> str:
        """Generate a comprehensive security report."""
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

        # Calculate summary statistics
        total_issues = sum(r.issue_count for r in results)
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        service_counts: Dict[str, int] = {}

        for result in results:
            if result.issue_count > 0:
                severity_counts[result.control.severity] += result.issue_count

            service = result.control.service or "UNKNOWN"
            service_counts[service] = service_counts.get(service, 0) + 1

        # Build report
        lines = [
            "# AWS Foundational Security Report",
            f"Generated: {timestamp}",
            f"Controls executed: {len(results)}",
            "",
            "## Executive Summary",
            "",
            f"**Total Security Issues**: {total_issues}",
            f"- Critical Severity: {severity_counts['CRITICAL']}",
            f"- High Severity: {severity_counts['HIGH']}",
            f"- Medium Severity: {severity_counts['MEDIUM']}",
            f"- Low Severity: {severity_counts['LOW']}",
            "",
            f"**Services Scanned**: {len(service_counts)}",
        ]

        for service, count in sorted(service_counts.items()):
            lines.append(f"- {service}: {count} controls")

        lines.extend(["", "## Security Check Results", ""])

        # Add individual check results
        for result in results:
            lines.extend([
                f"### {result.control.title} ({result.control.severity})",
                f"**Service**: {result.control.service}",
                f"**Description**: {result.control.description}",
                "",
                f"**{'✅ PASSED' if result.passed else '❌ FAILED'}**: "
                f"{'No issues found' if result.passed else f'{result.issue_count} issue(s) found'}",
                "",
                result.details,
                "",
                "---",
                ""
            ])

        return "\n".join(lines)

    def _run_single_check(self, control: SecurityControl) -> SecurityCheckResult:
        """Run a single security check."""
        query_result = self.client.execute_query(control.query)

        if query_result.error:
            return SecurityCheckResult(
                control=control,
                passed=False,
                issue_count=0,
                details=f"**⚠️ ERROR**: {query_result.error}"
            )

        issue_count = len(query_result.rows)
        passed = issue_count == 0

        if passed:
            details = "**✅ PASSED**: No issues found"
        else:
            details = f"**❌ FAILED**: {issue_count} issue(s) found\n\n"
            details += ResultFormatter.format_as_table(query_result, max_rows=25)

        return SecurityCheckResult(
            control=control,
            passed=passed,
            issue_count=issue_count,
            details=details
        )

    def _load_controls(self) -> List[SecurityControl]:
        """Load AWS Foundational Security controls."""
        return [
            SecurityControl(
                id="foundational_security_iam_1",
                title="[IAM.1] IAM policies should not allow full '*' administrative privileges",
                description="Checks whether IAM customer managed policies have administrator access with 'Effect': 'Allow' with 'Action': '*' over 'Resource': '*'",
                severity="HIGH",
                query="""
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
            ),
            SecurityControl(
                id="foundational_security_iam_5",
                title="[IAM.5] MFA should be enabled for all IAM users that have a console password",
                description="Checks whether AWS multi-factor authentication (MFA) is enabled for all IAM users that use a console password",
                severity="MEDIUM",
                query="""
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
            ),
            SecurityControl(
                id="foundational_security_s3_1",
                title="[S3.1] S3 Block Public Access setting should be enabled",
                description="Checks whether S3 public access block settings are configured at the account level",
                severity="MEDIUM",
                query="""
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
            ),
            SecurityControl(
                id="foundational_security_s3_2",
                title="[S3.2] S3 buckets should prohibit public read access",
                description="Checks whether your S3 buckets allow public read access by evaluating Block Public Access settings, bucket policy, and bucket ACL",
                severity="CRITICAL",
                query="""
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
            ),
            SecurityControl(
                id="foundational_security_ec2_2",
                title="[EC2.2] VPC default security groups should not allow inbound or outbound traffic",
                description="Checks that default security group of a VPC does not allow inbound or outbound traffic",
                severity="HIGH",
                query="""
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
            ),
            SecurityControl(
                id="foundational_security_ec2_3",
                title="[EC2.3] Attached EBS volumes should be encrypted at rest",
                description="Checks whether EBS volumes that are in an attached state are encrypted",
                severity="MEDIUM",
                query="""
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
            ),
            SecurityControl(
                id="foundational_security_cloudtrail_1",
                title="[CloudTrail.1] CloudTrail should be enabled and configured with at least one multi-Region trail",
                description="Checks that there is at least one multi-Region CloudTrail trail",
                severity="HIGH",
                query="""
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
            ),
            SecurityControl(
                id="foundational_security_ec2_15",
                title="[EC2.15] EC2 subnets should not automatically assign public IP addresses",
                description="Checks whether EC2 subnets have automatic assignment of public IP addresses enabled",
                severity="MEDIUM",
                query="""
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
            )
        ]