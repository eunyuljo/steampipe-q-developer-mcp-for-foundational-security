#!/usr/bin/env python3
"""Steampipe AWS MCP Server — query AWS infrastructure via Steampipe.

This is the main entry point for the modularized MCP server.
All functionality has been organized into modules in the src/ directory.
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from config import AppConfig
from mcp_tools import MCPToolsManager


def main():
    """Initialize and run the MCP server."""
    try:
        # Load configuration from environment variables
        config = AppConfig.load()

        # Initialize MCP tools manager with all components
        tools_manager = MCPToolsManager(config)

        # Run the MCP server
        tools_manager.run()

    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()