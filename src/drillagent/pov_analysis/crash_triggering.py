import os

from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    from drillagent.drill_agent import DrillAgent

class CrashTriggerAgent:
    # Responsible for triggering crashes based on analyzed paths
    def __init__(self, drill_agent: 'DrillAgent'):
        self.drill_agent = drill_agent
        self.config = drill_agent.config
        self.logger = drill_agent.logger
        self.tools = []
        self.tools.extend(drill_agent.agent_tools)
        self.tools.extend(drill_agent.agent_cov_tools) # For crash triggering, we also provide coverage tools.

    def run(self) -> None:
        self.logger.info("  [CrashTriggerAgent] Starting crash triggering attempts...")

