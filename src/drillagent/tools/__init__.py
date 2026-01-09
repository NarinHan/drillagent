"""
This module contains LLM agent tools for code repository exploration and analysis.

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
    FunctionCovTool
)

from .clangd_index_tools import (
    ClangdManager,
    FindFunctionDefTool,
    FindReferencesTool,
    GetCallHierarchyTool,
    GetHoverInfoTool
)

from .ast_grep_tools import (
    AstGrepManager,
    AstGrepFunctionSearchTool,
    AstGrepPatternSearchTool
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
    "FunctionCovTool",

    # Clangd-based code intelligence tools
    "ClangdManager",
    "FindFunctionDefTool",
    "FindReferencesTool",
    "GetCallHierarchyTool",
    "GetHoverInfoTool",

    # ast-grep based search tools
    "AstGrepManager",
    "AstGrepFunctionSearchTool",
    "AstGrepPatternSearchTool",
]
