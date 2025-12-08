
class PathExplorationAgent:
    # Responsible for exploring paths leading to vulnerabilities, fully utilizing the coverage feedback.
    def __init__(self, drill_agent):
        self.drill_agent = drill_agent
        self.config = drill_agent.config
        self.logger = drill_agent.logger
        self.llm = drill_agent.llm
        self.tools = drill_agent.agent_tools

