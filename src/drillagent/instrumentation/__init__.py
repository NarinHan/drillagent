"""
Instrumentation Module

This module handles code instrumentation for coverage tracking, distance calculation, and sanitizers.
"""

from .base_agent import BaseAgent, AgentState
from .distance_agent import DistanceAgent
from .config_generator import ConfigGeneratorAgent
from .coverage_agent import CoverageInstrumentAgent

# TODO: Import instrumentation components once created
# from .distance import DistanceCalculator
# from .sanitizer import MemorySanitizer

__all__ = [
    'BaseAgent', 
    'AgentState', 
    'DistanceAgent', 
    'ConfigGeneratorAgent',
    'CoverageInstrumentAgent'
]
