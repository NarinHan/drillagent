"""
Instrumentation Module

This module handles code instrumentation for coverage tracking, distance calculation, and sanitizers.
"""

from .base_agent import BaseAgent, AgentState
from .distance_agent import DistanceAgent
from .coverage_agent import CoverageInstrumentAgent

# ConfigGeneratorAgent is deprecated - use SecbTask directly from task_loader.sec_bench

__all__ = [
    'BaseAgent', 
    'AgentState', 
    'DistanceAgent', 
    'CoverageInstrumentAgent'
]
