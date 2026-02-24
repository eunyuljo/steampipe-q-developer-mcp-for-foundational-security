"""MCP tools for Steampipe AWS server."""

from typing import Optional, List
from mcp.server.fastmcp import FastMCP

from config import AppConfig
from steampipe_client import SteampipeClient, ResultFormatter
from security_checker import SecurityChecker
from report_generator import ReportGenerator


class MCPToolsManager:
    """Manager for all MCP tools."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.steampipe_client = SteampipeClient(config.steampipe)
        self.security_checker = SecurityChecker(self.steampipe_client)
        self.report_generator = ReportGenerator(self.steampipe_client, config.report)

        # Initialize FastMCP server
        self.mcp = FastMCP(config.mcp.name, instructions=config.mcp.instructions)
        self._register_tools()

    def _register_tools(self):
        """Register all MCP tools."""

        @self.mcp.tool()
        def query_aws(sql: str, timeout: int = None) -> str:
            """Execute a Steampipe SQL query against AWS infrastructure.

            Args:
                sql: SQL query to run (e.g. "select instance_id, instance_type from aws_ec2_instance")
                timeout: Query timeout in seconds (default from config)
            """
            result = self.steampipe_client.execute_query(sql, timeout)
            return ResultFormatter.format_as_table(result)

        @self.mcp.tool()
        def list_tables(keyword: str = "") -> str:
            """List available Steampipe AWS tables, optionally filtered by keyword.

            Args:
                keyword: Optional keyword to filter table names (e.g. "ec2", "s3", "iam")
            """
            sql = (
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'aws' ORDER BY table_name"
            )
            result = self.steampipe_client.execute_query(sql)

            if result.error:
                return f"Error: {result.error}"

            tables = [r["table_name"] for r in result.rows]

            if keyword:
                kw = keyword.lower()
                tables = [t for t in tables if kw in t.lower()]

            if not tables:
                return f"No tables found matching '{keyword}'." if keyword else "No tables found."

            response = f"Found {len(tables)} table{'s' if len(tables) != 1 else ''}"
            if keyword:
                response += f" matching '{keyword}'"
            response += ":\n\n" + "\n".join(tables)
            return response

        @self.mcp.tool()
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
            result = self.steampipe_client.execute_query(sql)

            if result.error:
                return f"Error: {result.error}"

            if not result.rows:
                return f"Table '{table_name}' not found. Use list_tables to see available tables."

            lines = [f"Table: {table_name}", f"Columns ({len(result.rows)}):", ""]
            lines.append(f"{'Column':<40} {'Type':<20} {'Nullable'}")
            lines.append(f"{'-'*40} {'-'*20} {'-'*8}")
            for row in result.rows:
                lines.append(
                    f"{row['column_name']:<40} {row['data_type']:<20} {row['is_nullable']}"
                )
            return "\n".join(lines)

        @self.mcp.tool()
        def get_aws_summary() -> str:
            """Generate a summary report of key AWS resources.

            Covers: EC2, Lambda, S3, EBS, RDS, DynamoDB, VPC, Subnets,
            Security Groups, IAM Users/Roles, SNS, CloudWatch, CloudTrail, etc.
            """
            data = self.report_generator._collect_all_data()
            sections = []

            queries = self.report_generator._get_summary_queries()
            for title, _ in queries[:12]:  # Show first 12 categories
                table_data = data.get(title, {"columns": [], "rows": []})

                if table_data.get("error"):
                    sections.append(f"## {title}\n\nError: {table_data['error']}")
                else:
                    rows = table_data.get("rows", [])
                    body = ResultFormatter.format_as_table(
                        type('QueryResult', (), table_data)(),
                        max_rows=50
                    ) if rows else "None found."
                    sections.append(f"## {title} ({len(rows)})\n\n{body}")

            return "# AWS Infrastructure Summary\n\n" + "\n\n---\n\n".join(sections)

        @self.mcp.tool()
        def get_report_data() -> str:
            """Collect all AWS resource data and return a compact statistical summary.

            Call this FIRST, then use the returned summary to write analysis.
            Pass the analysis to generate_html_report() to produce the final HTML.
            """
            return self.report_generator.generate_summary_data()

        @self.mcp.tool()
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
            return self.report_generator.generate_html_report(analysis)

        @self.mcp.tool()
        def run_security_checks(check_ids: str = "") -> str:
            """Run AWS Foundational Security Best Practices compliance checks.

            Args:
                check_ids: Optional comma-separated list of check IDs to run.
                          If empty, runs basic 8 security controls.
            """
            if check_ids.strip():
                requested_ids = [cid.strip() for cid in check_ids.split(",")]
                # Validate IDs exist
                available_ids = [c.id for c in self.security_checker.controls]
                valid_ids = [id for id in requested_ids if id in available_ids]
                if not valid_ids:
                    return f"Error: No valid check IDs found in '{check_ids}'"
                results = self.security_checker.run_checks(valid_ids)
            else:
                # Run basic 8 controls by default
                basic_ids = [c.id for c in self.security_checker.controls[:8]]
                results = self.security_checker.run_checks(basic_ids)

            return self.security_checker.generate_report(results)

        @self.mcp.tool()
        def run_all_foundational_security_checks() -> str:
            """Run all available AWS Foundational Security Best Practices compliance checks.

            Executes all implemented security controls for comprehensive scanning.
            """
            results = self.security_checker.run_checks()
            report = self.security_checker.generate_report(results)

            # Add coverage information
            total_controls = len(self.security_checker.controls)
            coverage = f"\nControls executed: {total_controls}\n"
            coverage += f"Coverage: This represents core AWS Foundational Security controls\n"

            return report.replace("# AWS Foundational Security Report",
                                f"# Comprehensive AWS Foundational Security Report{coverage}")

    def run(self):
        """Run the MCP server."""
        self.mcp.run()