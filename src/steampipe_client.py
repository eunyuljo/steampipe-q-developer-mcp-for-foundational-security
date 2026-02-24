"""Steampipe client for executing queries and formatting results."""

import json
import subprocess
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from config import SteampipeConfig


@dataclass
class QueryResult:
    """Steampipe query result."""
    columns: List[Dict[str, str]]
    rows: List[Dict[str, Any]]
    error: Optional[str] = None


class SteampipeClient:
    """Client for interacting with Steampipe CLI."""

    def __init__(self, config: SteampipeConfig):
        self.config = config
        self._cache: Dict[str, QueryResult] = {}
        self._cache_times: Dict[str, float] = {}

    def execute_query(self, sql: str, timeout: Optional[int] = None) -> QueryResult:
        """Execute a Steampipe SQL query and return parsed result."""
        timeout = timeout or self.config.default_timeout

        # Check cache first
        cache_key = f"{sql}:{timeout}"
        if self._is_cached(cache_key):
            return self._cache[cache_key]

        try:
            result = subprocess.run(
                [self.config.command, "query", "--output", "json", sql],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            error_msg = f"Query timed out after {timeout} seconds"
            return QueryResult(columns=[], rows=[], error=error_msg)
        except FileNotFoundError:
            error_msg = "Steampipe CLI not found. Ensure it is installed and on PATH."
            return QueryResult(columns=[], rows=[], error=error_msg)

        if result.returncode != 0:
            error_msg = f"Steampipe error: {result.stderr.strip()}"
            return QueryResult(columns=[], rows=[], error=error_msg)

        if not result.stdout.strip():
            query_result = QueryResult(columns=[], rows=[])
        else:
            try:
                data = json.loads(result.stdout)
                query_result = QueryResult(
                    columns=data.get("columns", []),
                    rows=data.get("rows", [])
                )
            except json.JSONDecodeError as e:
                error_msg = f"Error parsing Steampipe output: {e}"
                return QueryResult(columns=[], rows=[], error=error_msg)

        # Cache the result
        self._cache[cache_key] = query_result
        self._cache_times[cache_key] = time.time()

        return query_result

    def _is_cached(self, cache_key: str) -> bool:
        """Check if query result is cached and still valid."""
        if cache_key not in self._cache:
            return False

        cache_age = time.time() - self._cache_times[cache_key]
        return cache_age < self.config.cache_ttl

    def clear_cache(self) -> None:
        """Clear the query result cache."""
        self._cache.clear()
        self._cache_times.clear()


class ResultFormatter:
    """Formatter for Steampipe query results."""

    @staticmethod
    def format_as_table(result: QueryResult, max_rows: Optional[int] = None) -> str:
        """Format query result as a readable text table."""
        if result.error:
            return f"Error: {result.error}"

        if not result.rows:
            return "No results."

        rows = result.rows
        if max_rows and len(rows) > max_rows:
            rows = rows[:max_rows]
            truncated = True
        else:
            truncated = False

        columns = [c["name"] for c in result.columns]
        if not columns and rows:
            columns = list(rows[0].keys())

        # Calculate column widths
        col_widths = {c: len(c) for c in columns}
        for row in rows:
            for c in columns:
                val = str(row.get(c, ""))
                col_widths[c] = max(col_widths[c], min(len(val), 60))

        # Build table
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

        result_text = "\n".join(lines)
        result_text += f"\n\n({len(rows)} row{'s' if len(rows) != 1 else ''})"
        if truncated:
            result_text += f" — truncated to {max_rows}"

        return result_text

    @staticmethod
    def format_as_html_table(result: QueryResult, max_rows: int = 50) -> str:
        """Convert query result to HTML table."""
        if result.error:
            return f'<p class="error">Error: {result.error}</p>'

        rows = result.rows
        columns = [c["name"] for c in result.columns]

        if not columns and rows:
            columns = list(rows[0].keys())

        if not rows:
            return '<p class="empty">No resources found.</p>'

        truncated = len(rows) > max_rows
        display_rows = rows[:max_rows]

        parts = ['<table><thead><tr>']
        for c in columns:
            parts.append(f'<th>{ResultFormatter._html_escape(c)}</th>')
        parts.append('</tr></thead><tbody>')

        for row in display_rows:
            parts.append('<tr>')
            for c in columns:
                val = str(row.get(c, ""))
                parts.append(f'<td>{ResultFormatter._html_escape(val)}</td>')
            parts.append('</tr>')

        parts.append('</tbody></table>')
        parts.append(f'<p class="row-count">{len(rows)} row{"s" if len(rows)!=1 else ""}'
                     + (f' (showing first {max_rows})' if truncated else '')
                     + '</p>')

        return "\n".join(parts)

    @staticmethod
    def _html_escape(text: str) -> str:
        """Escape HTML special characters."""
        return (str(text)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;"))