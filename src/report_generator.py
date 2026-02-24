"""HTML report generation for AWS infrastructure analysis."""

from datetime import datetime, timezone
from typing import Dict, List, Any
from pathlib import Path
from steampipe_client import SteampipeClient, ResultFormatter
from config import ReportConfig


class ReportGenerator:
    """HTML report generator for AWS infrastructure."""

    def __init__(self, steampipe_client: SteampipeClient, config: ReportConfig):
        self.client = steampipe_client
        self.config = config
        self._cached_data: Dict[str, Any] = {}

    def generate_summary_data(self) -> str:
        """Generate compact statistical summary for AI analysis."""
        data = self._collect_all_data()
        errors = [t for t, d in data.items() if d.get("error")]
        summary = self._summarize_data(data)

        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        header = (
            f"AWS Account: 977099011692 | Region: ap-northeast-2\n"
            f"Collected: {timestamp}\n"
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

    def generate_html_report(self, analysis: Dict[str, str]) -> str:
        """Generate HTML infrastructure report with AI analysis."""
        data = self._cached_data or self._collect_all_data()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # Dashboard counts
        dashboard_items = []
        for label, table_name in self.config.dashboard_items:
            count = len(data.get(table_name, {}).get("rows", []))
            dashboard_items.append((label, count))

        # Generate HTML sections
        html_content = self._build_html_document(
            analysis=analysis,
            data=data,
            dashboard_items=dashboard_items,
            timestamp=timestamp
        )

        # Save to file
        output_path = Path(self.config.output_path)
        output_path.write_text(html_content, encoding="utf-8")

        return f"Report saved to {output_path} ({len(html_content):,} bytes)"

    def _collect_all_data(self) -> Dict[str, Any]:
        """Collect data from all summary queries."""
        if self._cached_data:
            return self._cached_data

        # Summary queries for 28 categories
        summary_queries = self._get_summary_queries()

        result = {}
        for title, sql in summary_queries:
            query_result = self.client.execute_query(sql)
            if query_result.error:
                result[title] = {"columns": [], "rows": [], "error": query_result.error}
            else:
                result[title] = {
                    "columns": query_result.columns,
                    "rows": query_result.rows
                }

        self._cached_data = result
        return result

    def _summarize_data(self, data: Dict[str, Any]) -> str:
        """Produce compact statistical summary for AI analysis."""
        lines = []

        def rows(title: str) -> List[Dict]:
            return data.get(title, {}).get("rows", [])

        def count(title: str) -> int:
            return len(rows(title))

        # Compute section
        ec2 = rows("EC2 Instances")
        running = [r for r in ec2 if r.get("instance_state") == "running"]
        stopped = [r for r in ec2 if r.get("instance_state") == "stopped"]

        lines.extend([
            "[Compute]",
            f"  EC2: {len(ec2)} total ({len(running)} running, {len(stopped)} stopped)",
            f"  ASG: {count('Auto Scaling Groups')} | ECS: {count('ECS Clusters')} | EKS: {count('EKS Clusters')}",
            f"  Lambda: {count('Lambda Functions')} functions"
        ])

        # Storage section
        s3 = rows("S3 Buckets")
        versioned = sum(1 for r in s3 if str(r.get("versioning_enabled", "")).lower() == "true")
        ebs = rows("EBS Volumes")
        available_ebs = [r for r in ebs if r.get("state") == "available"]

        lines.extend([
            "[Storage]",
            f"  S3: {len(s3)} buckets ({versioned} versioned, {len(s3)-versioned} not)",
            f"  EBS: {len(ebs)} volumes ({len(available_ebs)} unattached)",
            f"  EFS: {count('EFS File Systems')} file systems"
        ])

        # Continue with other sections...
        lines.extend([
            "[Database/Cache]",
            f"  RDS: {count('RDS Instances')} | DynamoDB: {count('DynamoDB Tables')} | ElastiCache: {count('ElastiCache Clusters')}",
            "[Security/Governance]",
            f"  IAM Users: {count('IAM Users')} | IAM Roles: {count('IAM Roles')}",
            f"  CloudTrail: {count('CloudTrail Trails')} trails",
            "[Messaging/Monitoring]",
            f"  SNS: {count('SNS Topics')} topics | SQS: {count('SQS Queues')} queues",
            f"  CloudWatch Alarms: {count('CloudWatch Alarms')}"
        ])

        return "\n".join(lines)

    def _build_html_document(self, analysis: Dict[str, str], data: Dict[str, Any],
                           dashboard_items: List[tuple], timestamp: str) -> str:
        """Build complete HTML document."""
        css = self._get_css_styles()

        # Dashboard HTML
        dash_html = "\n".join(
            f'<div class="card"><div class="num">{count}</div><div class="label">{label}</div></div>'
            for label, count in dashboard_items
        )

        # Sections HTML
        sections_html = []

        # Executive summary
        sections_html.append(
            f'<div class="section"><h2>Executive Summary</h2>'
            f'<div class="ai-box"><strong>AI Analysis</strong>\n{analysis.get("executive_summary", "")}</div>'
            f'</div>'
        )

        # Data sections with AI analysis + tables
        section_mappings = {
            "compute_analysis": ["EC2 Instances", "Lambda Functions"],
            "storage_analysis": ["S3 Buckets", "EBS Volumes"],
            "database_analysis": ["DynamoDB Tables"],
            "networking_analysis": ["VPCs", "Subnets", "Security Groups"],
            "security_analysis": ["IAM Users", "IAM Roles"],
            "monitoring_analysis": ["SNS Topics", "CloudWatch Alarms"]
        }

        for key, tables in section_mappings.items():
            label = key.replace("_", " ").title()
            sec = f'<div class="section"><h2>{label}</h2>'
            sec += f'<div class="ai-box"><strong>AI Analysis</strong>\n{analysis.get(key, "")}</div>'

            for table in tables:
                table_data = data.get(table, {"columns": [], "rows": []})
                sec += f'<h3>{table} ({len(table_data.get("rows", []))})</h3>'
                if table_data.get("error"):
                    sec += f'<p class="empty">Error: {table_data["error"]}</p>'
                else:
                    sec += ResultFormatter.format_as_html_table(
                        type('QueryResult', (), table_data)(),  # Convert dict to object
                        max_rows=self.config.max_rows_per_table
                    )
            sec += '</div>'
            sections_html.append(sec)

        # Compliance analysis
        sections_html.append(
            f'<div class="section"><h2>Security Compliance</h2>'
            f'<div class="ai-box"><strong>AI Analysis</strong>\n{analysis.get("compliance_analysis", "")}</div>'
            f'</div>'
        )

        # Recommendations
        sections_html.append(
            f'<div class="section"><h2>Recommendations</h2>'
            f'<div class="reco-box"><strong>AI Recommendations</strong>\n{analysis.get("recommendations", "")}</div>'
            f'</div>'
        )

        return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AWS Infrastructure Report — {timestamp}</title>
<style>{css}</style>
</head>
<body>
<div class="container">
<header>
  <h1>AWS Infrastructure Report</h1>
  <div class="meta">Account 977099011692 · ap-northeast-2 · Generated {timestamp}</div>
</header>
<div class="dashboard">{dash_html}</div>
{"".join(sections_html)}
<footer>Generated by Steampipe AWS MCP Server · Data queried via Steampipe v2.3.5</footer>
</div>
</body>
</html>"""

    def _get_summary_queries(self) -> List[tuple]:
        """Get all summary queries for data collection."""
        return [
            ("EC2 Instances", "SELECT instance_id, instance_state, instance_type, region FROM aws_ec2_instance ORDER BY instance_state, region"),
            ("Lambda Functions", "SELECT name, runtime, memory_size, region FROM aws_lambda_function ORDER BY name"),
            ("S3 Buckets", "SELECT name, region, versioning_enabled FROM aws_s3_bucket ORDER BY name"),
            ("EBS Volumes", "SELECT volume_id, volume_type, size, state, region FROM aws_ebs_volume ORDER BY state, region"),
            ("DynamoDB Tables", "SELECT name, table_status, item_count, table_size_bytes, region FROM aws_dynamodb_table ORDER BY name"),
            ("VPCs", "SELECT vpc_id, cidr_block, is_default, state, region FROM aws_vpc ORDER BY region"),
            ("Subnets", "SELECT subnet_id, vpc_id, cidr_block, availability_zone, map_public_ip_on_launch FROM aws_vpc_subnet ORDER BY vpc_id, availability_zone"),
            ("Security Groups", "SELECT group_id, group_name, vpc_id, region FROM aws_vpc_security_group ORDER BY vpc_id, group_name"),
            ("IAM Users", "SELECT name, create_date, mfa_enabled FROM aws_iam_user ORDER BY name"),
            ("IAM Roles", "SELECT name, create_date, max_session_duration FROM aws_iam_role WHERE path = '/' ORDER BY name"),
            ("SNS Topics", "SELECT title, region FROM aws_sns_topic ORDER BY title"),
            ("CloudWatch Alarms", "SELECT name, state_value, metric_name, namespace, region FROM aws_cloudwatch_alarm ORDER BY state_value, name"),
            ("CloudTrail Trails", "SELECT name, is_multi_region_trail, is_logging, region FROM aws_cloudtrail_trail ORDER BY name"),
            ("Auto Scaling Groups", "SELECT name, min_size, max_size, desired_capacity, region FROM aws_ec2_autoscaling_group ORDER BY name"),
            ("ECS Clusters", "SELECT cluster_name, status, active_services_count, running_tasks_count, region FROM aws_ecs_cluster ORDER BY cluster_name"),
            ("EKS Clusters", "SELECT name, status, version, region FROM aws_eks_cluster ORDER BY name"),
            ("EFS File Systems", "SELECT file_system_id, life_cycle_state, size_in_bytes, region FROM aws_efs_file_system ORDER BY file_system_id"),
            ("RDS Instances", "SELECT db_instance_identifier, engine, class, status FROM aws_rds_db_instance ORDER BY status"),
            ("ElastiCache Clusters", "SELECT cache_cluster_id, engine, cache_node_type, cache_cluster_status, region FROM aws_elasticache_cluster ORDER BY cache_cluster_id"),
            ("SQS Queues", "SELECT title, fifo_queue, region FROM aws_sqs_queue ORDER BY title"),
        ]

    def _get_css_styles(self) -> str:
        """Get CSS styles for the HTML report."""
        return """\
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: 'Segoe UI',system-ui,-apple-system,sans-serif;
       color:#1a1a2e; background:#f0f2f5; padding:24px; line-height:1.5; }
.container { max-width:1200px; margin:0 auto; }
header { background:linear-gradient(135deg,#232f3e 0%,#37475a 100%);
         color:#fff; padding:32px 40px; border-radius:12px; margin-bottom:28px; }
header h1 { font-size:26px; font-weight:700; }
header .meta { font-size:13px; color:#a0b4c8; margin-top:6px; }
.dashboard { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr));
             gap:14px; margin-bottom:28px; }
.card { background:#fff; border-radius:10px; padding:18px 20px;
        box-shadow:0 1px 3px rgba(0,0,0,.08); text-align:center; }
.card .num { font-size:28px; font-weight:700; color:#232f3e; }
.card .label { font-size:12px; color:#666; margin-top:2px; text-transform:uppercase;
               letter-spacing:.5px; }
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
.error { color:#d32f2f; font-weight:600; padding:12px 0; }
.row-count { font-size:12px; color:#888; margin-top:6px; }
.reco-box { background:#eef6ee; border-left:4px solid #2e7d32;
            padding:16px 20px; border-radius:0 8px 8px 0;
            font-size:14px; white-space:pre-wrap; }
.reco-box strong { color:#2e7d32; }
footer { text-align:center; color:#999; font-size:12px; margin-top:32px; }
@media print { body { background:#fff; padding:0; }
               .section { box-shadow:none; break-inside:avoid; } }
"""