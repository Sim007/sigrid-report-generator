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

_RISK_LABEL = {0: "critical", 1: "high", 2: "medium", 3: "low", 4: "no_risk"}
_RISK_PROPERTY_NAMES = [
    "sigrid:risk:vulnerability",
    "sigrid:risk:legal",
    "sigrid:risk:freshness",
    "sigrid:risk:stability",
    "sigrid:risk:management",
    "sigrid:risk:activity",
]


class OSHMetricsBase:
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

    def _get_risk_value(self, properties: list, risk_name: str) -> int:
        """Return integer risk level (0=critical … 4=no_risk) for a single property name."""
        risk_mapping = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for prop in properties:
            if prop.get("name") == risk_name:
                return risk_mapping.get(prop.get("value"), 4)
        return 4

    def _categorize_risk_level(self, risk_level: int, risk_counts: dict) -> None:
        """Increment the appropriate risk count based on the risk level."""
        risk_counts[_RISK_LABEL.get(risk_level, "no_risk")] += 1

    def _update_library_risk(
        self, lib_id: str, highest_risk: int, processed: dict, risk_counts: dict
    ) -> None:
        """Update risk counts when a library is seen for the first time or with a higher risk."""
        if lib_id in processed:
            risk_counts[_RISK_LABEL[processed[lib_id]]] -= 1
        processed[lib_id] = highest_risk
        self._categorize_risk_level(highest_risk, risk_counts)

    def _highest_risk_for_component(self, component: dict) -> int:
        """Return the highest (lowest integer) risk level across all OSH categories for a component."""
        props = component.get("properties", [])
        return min(self._get_risk_value(props, name) for name in _RISK_PROPERTY_NAMES)
