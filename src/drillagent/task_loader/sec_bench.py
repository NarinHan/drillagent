from drillagent.drill_agent import DrillAgent
from drillagent.config import AgentConfig


class RawSecbTaskLoader:
    # Responsible for loading security benchmark tasks (from json files)

    def create_agent_from_task(self, task_data):
        config = AgentConfig(
            target_repo=task_data.get("repo_path", "."),
            cve_id=task_data.get("cve_id")
        )
        agent = DrillAgent(config)
        return agent


class SecbTaskLoader:
    # TODO: To be compatible with SEC-bench official eval process.
    pass

