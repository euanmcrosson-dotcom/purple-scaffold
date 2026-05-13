"""
Reproducible Attack Scenarios Runner
"""
from attacks.mcp_prompt_injection import MCPAttackSimulator, create_standard_scenarios
from core.orchestrator import PurpleOrchestrator
import json
from datetime import datetime

class ReproducibleScenarioRunner:
    def __init__(self):
        self.orchestrator = PurpleOrchestrator()
        self.simulator = MCPAttackSimulator()
        self.results = []

    def setup_standard_agents(self):
        self.orchestrator.add_agent("RedAgent", "Adversary")
        self.orchestrator.add_agent("BlueAgent", "Defender")
        self.orchestrator.add_agent("PurpleAgent", "Observer")

    async def run_all_scenarios(self):
        """Run all reproducible attack scenarios"""
        self.setup_standard_agents()
        scenarios = create_standard_scenarios()

        for scenario in scenarios:
            print(f"\n=== Running Scenario: {scenario.name} ===")
            attack_result = self.simulator.simulate_attack(scenario, None)
            
            # Run multi-agent analysis
            analysis = await self.orchestrator.run_multi_agent_loop(
                f"Analyze this attack scenario: {scenario.description}"
            )
            
            self.results.append({
                "timestamp": datetime.now().isoformat(),
                "scenario": scenario.name,
                "attack_result": attack_result,
                "orchestration_result": analysis
            })

        self.save_results()

    def save_results(self):
        with open("results/last_run.json", "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"\n✅ Saved {len(self.results)} reproducible scenarios to results/last_run.json")

if __name__ == "__main__":
    runner = ReproducibleScenarioRunner()
    asyncio.run(runner.run_all_scenarios())
