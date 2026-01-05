"""
Tools Module

This module contains LLM agent tools for code repository exploration and analysis.

Submodules:
- basic_tools: Core repository exploration tools (read files, grep, find, list, tree)
- cov_query_tools: Coverage query tools for analyzing code coverage data
- code_index_tools: Code indexing and analysis tools (planned)
- python_tools: Python-specific analysis tools (planned)

All tools inherit from AgentTool base class and support both Claude and OpenAI schemas.
"""

from .basic_tools import (
    AgentTool,
    ReadFileTool,
    GrepTool,
    FindFileTool,
    ListDirTool,
    TreeTool
)

from .cov_query_tools import (
    FuncLineCovTool,
    FuncObjectCovTool
)

__all__ = [
    # Base class
    "AgentTool",

    # Basic repository exploration tools
    "ReadFileTool",
    "GrepTool",
    "FindFileTool",
    "ListDirTool",
    "TreeTool",

    # Coverage query tools
    "FuncLineCovTool",
    "FuncObjectCovTool",
]
