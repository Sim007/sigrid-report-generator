#  Copyright Software Improvement Group
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from functools import cached_property
from abc import ABC, abstractmethod
from datetime import date

_SEVERITY_LEVELS = ("critical", "high", "medium", "low")

def vulnerability_severity_counts(vulnerabilities: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"total": len(vulnerabilities), "critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for vuln in vulnerabilities:
        severities = {r["severity"].lower() for r in vuln.get("ratings", [])}
        for level in _SEVERITY_LEVELS:
            if level in severities:
                counts[level] += 1
                break
        else:
            counts["unknown"] += 1
    return counts

def map_cves_to_affected_libraries(components: list[dict], vulnerabilities: list[dict]) -> dict[str, dict]:
    components_by_ref = {c["bom-ref"]: c for c in components}
    result = {}
    for vuln in vulnerabilities:
        affected = [
            {"name": c["name"], "version": c["version"], "purl": c.get("purl")}
            for ref in vuln.get("affects", [])
            if (c := components_by_ref.get(ref["ref"]))
        ]
        result[vuln["id"]] = {"count": len(affected), "libraries": affected}
    return result

def _find_cyclonedx_property_value(properties: list[dict], key: str) -> str | None:
    for prop in properties:
        if prop.get("name") == key:
            return prop.get("value")
    return None

def component_version_staleness_days(components: list[dict]) -> list[int]:
    result = []
    today = date.today()
    for component in components:
        properties = component.get("properties")
        if not properties:
            continue
        next_release_date = _find_cyclonedx_property_value(properties, "sigrid:next:releaseDate")
        if next_release_date:
            result.append((today - date.fromisoformat(next_release_date)).days)
    return result

class OSHMetricsBase(ABC):
    """Base class for OSH (Open Source Health) metrics.

    Provides common metrics calculations for both system-level and portfolio-level OSH data.
    Subclasses must provide risk distribution properties and dependencies_count.
    """

    @cached_property
    def vulnerabilities_count(self) -> int:
        """Number of dependencies with vulnerabilities (critical to low)."""
        return sum(self.vulnerability_risk_distribution[0:4])

    @cached_property
    def vulnerabilities_fraction(self) -> float:
        if not self.vulnerabilities_count or not self.dependencies_count:
            return 0.0
        return max(self.vulnerabilities_count / self.dependencies_count, 0.01)

    @cached_property
    def outdated_count(self) -> int:
        """Number of outdated dependencies (critical to medium freshness risk)."""
        return sum(self.freshness_risk_distribution[0:3])

    @cached_property
    def outdated_fraction(self) -> float:
        if not self.outdated_count or not self.dependencies_count:
            return 0.0
        return max(self.outdated_count / self.dependencies_count, 0.01)

    @cached_property
    def legal_risk_count(self) -> int:
        """Number of dependencies with restrictive licenses (critical to medium)."""
        return sum(self.legal_risk_distribution[0:3])

    @cached_property
    def legal_risk_fraction(self) -> float:
        if not self.legal_risk_count or not self.dependencies_count:
            return 0.0
        return max(self.legal_risk_count / self.dependencies_count, 0.01)

    @cached_property
    def unmanaged_count(self) -> int:
        """Number of unmanaged dependencies (all risk levels)."""
        return sum(self.management_risk_distribution[0:4])

    @cached_property
    def unmanaged_fraction(self) -> float:
        if not self.unmanaged_count or not self.dependencies_count:
            return 0.0
        return max(self.unmanaged_count / self.dependencies_count, 0.01)

    @cached_property
    def activity_risk_count(self) -> int:
        """Number of dependencies with activity risks."""
        return sum(self.activity_risk_distribution[0:4])

    @cached_property
    def activity_risk_fraction(self) -> float:
        if not self.activity_risk_count or not self.dependencies_count:
            return 0.0
        return max(self.activity_risk_count / self.dependencies_count, 0.01)

    @cached_property
    def risk_distributions(self) -> dict[str, list[int]]:
        """Dictionary of all risk distributions for chart rendering."""
        return {
            "vulnerability": self.vulnerability_risk_distribution,
            "legal": self.legal_risk_distribution,
            "freshness": self.freshness_risk_distribution,
            "stability": self.stability_risk_distribution,
            "management": self.management_risk_distribution,
            "activity": self.activity_risk_distribution,
        }

    @property
    @abstractmethod
    def vulnerability_distribution(self) -> dict[str, int]: ...

    @property
    @abstractmethod
    def map_vulnerabilities_to_libraries(self) -> dict[str, dict]: ...

    @property
    @abstractmethod
    def age_distribution(self) -> list[int]: ...

