"""
Instrumentation Module

This module handles code instrumentation for coverage tracking, distance calculation, and sanitizers.
"""

from .base_agent import BaseAgent, AgentState
from .distance_agent import DistanceAgent
from .base_instr_agent import BaseInstrAgent
from .coverage_agent import CoverageInstrumentAgent

# TODO: Import instrumentation components once created
# from .distance import DistanceCalculator
# from .sanitizer import MemorySanitizer

__all__ = [
    # 'BaseAgent', 
    # 'AgentState', 
    # 'DistanceAgent', 

    # LHY: Now only these classes should be used by DrillAgent main workflow.
    'BaseInstrAgent',
    'CoverageInstrumentAgent'
]
