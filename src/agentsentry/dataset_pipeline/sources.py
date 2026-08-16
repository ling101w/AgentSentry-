from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SourceSpec:
    key: str
    dataset: str
    directory: str
    repo_url: str
    threat_primary: str
    threat_secondary: tuple[str, ...] = ()
    raw_format: str = ""
    registry_aliases: tuple[str, ...] = ()


SOURCE_SPECS: tuple[SourceSpec, ...] = (
    SourceSpec(
        key="redteamcua",
        dataset="RedTeamCUA",
        directory="RedTeamCUA",
        repo_url="https://github.com/OSU-NLP-Group/RedTeamCUA.git",
        threat_primary="T2",
        raw_format="json",
        registry_aliases=("RedTeamCUA / RTC-Bench",),
    ),
    SourceSpec(
        key="msb",
        dataset="MSB",
        directory="MSB",
        repo_url="https://github.com/dongsenzhang/MSB.git",
        threat_primary="T4",
        threat_secondary=("T3",),
        raw_format="jsonl",
        registry_aliases=("MCP Security Bench（MSB）", "MCP Security Bench (MSB)"),
    ),
    SourceSpec(
        key="mcpsecbench",
        dataset="MCPSecBench",
        directory="MCPSecBench",
        repo_url="https://github.com/AIS2Lab/MCPSecBench.git",
        threat_primary="T4",
        threat_secondary=("T3",),
        raw_format="json",
    ),
    SourceSpec(
        key="memorygraft",
        dataset="MemoryGraft",
        directory="Agent-Memory-Poisoning",
        repo_url="https://github.com/Jacobhhy/Agent-Memory-Poisoning.git",
        threat_primary="T5",
        raw_format="json",
    ),
    SourceSpec(
        key="agentdojo",
        dataset="AgentDojo",
        directory="AgentDojo",
        repo_url="https://github.com/ethz-spylab/agentdojo.git",
        threat_primary="T2",
        threat_secondary=("T3",),
        raw_format="python",
    ),
    SourceSpec(
        key="injecagent",
        dataset="InjecAgent",
        directory="InjecAgent",
        repo_url="https://github.com/uiuc-kang-lab/InjecAgent.git",
        threat_primary="T2",
        threat_secondary=("T3",),
        raw_format="json",
    ),
    SourceSpec(
        key="deeptrap",
        dataset="DeepTrap",
        directory="DeepTrap",
        repo_url="https://github.com/ZJUICSR/DeepTrap.git",
        threat_primary="T7",
        raw_format="jsonl",
        registry_aliases=("DeepTrap / OpenClaw execution-context benchmark",),
    ),
)

SOURCE_BY_KEY = {item.key: item for item in SOURCE_SPECS}
SOURCE_BY_DATASET = {item.dataset.casefold(): item for item in SOURCE_SPECS}
for _spec in SOURCE_SPECS:
    for _alias in _spec.registry_aliases:
        SOURCE_BY_DATASET[_alias.casefold()] = _spec


def resolve_source(value: str) -> SourceSpec | None:
    normalized = value.strip().casefold()
    return SOURCE_BY_KEY.get(normalized) or SOURCE_BY_DATASET.get(normalized)
