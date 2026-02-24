"""Configuration management for Steampipe AWS MCP Server."""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class SteampipeConfig:
    """Steampipe connection configuration."""
    command: str = "steampipe"
    default_timeout: int = 30
    cache_ttl: int = 300  # 5 minutes


@dataclass
class ReportConfig:
    """Report generation configuration."""
    output_path: str = "report.html"
    max_rows_per_table: int = 50
    dashboard_items: list = None

    def __post_init__(self):
        if self.dashboard_items is None:
            self.dashboard_items = [
                ("EC2", "EC2 Instances"),
                ("Lambda", "Lambda Functions"),
                ("S3", "S3 Buckets"),
                ("EBS", "EBS Volumes"),
                ("RDS", "RDS Instances"),
                ("DynamoDB", "DynamoDB Tables"),
                ("VPCs", "VPCs"),
                ("Subnets", "Subnets"),
                ("Security Groups", "Security Groups"),
                ("IAM Users", "IAM Users"),
                ("IAM Roles", "IAM Roles"),
                ("Secrets", "Secrets Manager Secrets"),
            ]


@dataclass
class MCPConfig:
    """MCP Server configuration."""
    name: str = "steampipe-aws"
    instructions: str = (
        "This server queries AWS infrastructure through Steampipe. "
        "Use list_tables to discover available tables, describe_table to see columns, "
        "and query_aws to run SQL queries against AWS resources."
    )


@dataclass
class AppConfig:
    """Main application configuration."""
    steampipe: SteampipeConfig
    report: ReportConfig
    mcp: MCPConfig

    @classmethod
    def load(cls, config_file: Optional[str] = None) -> 'AppConfig':
        """Load configuration from file or environment variables."""
        # For now, return defaults. Later can add YAML/JSON file loading
        return cls(
            steampipe=SteampipeConfig(
                command=os.getenv("STEAMPIPE_CMD", "steampipe"),
                default_timeout=int(os.getenv("STEAMPIPE_TIMEOUT", "30")),
                cache_ttl=int(os.getenv("CACHE_TTL", "300"))
            ),
            report=ReportConfig(
                output_path=os.getenv("REPORT_OUTPUT", "report.html"),
                max_rows_per_table=int(os.getenv("MAX_ROWS", "50"))
            ),
            mcp=MCPConfig(
                name=os.getenv("MCP_NAME", "steampipe-aws")
            )
        )