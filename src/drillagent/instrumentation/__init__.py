"""
Instrumentation Module

This module handles code instrumentation for coverage tracking, distance calculation, and sanitizers.
"""

from .base_agent import BaseAgent, AgentState
from .instrumentation_agent import InstrumentationAgent
from .config_generator import ConfigGeneratorAgent

# TODO: Import instrumentation components once created
# from .coverage import CoverageInstrument
# from .distance import DistanceCalculator
# from .sanitizer import MemorySanitizer

__all__ = ['BaseAgent', 'AgentState', 'InstrumentationAgent', 'ConfigGeneratorAgent']
