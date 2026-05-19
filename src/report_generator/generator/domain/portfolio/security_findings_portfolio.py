from functools import cached_property
from itertools import chain

from report_generator.generator.context import sigrid_api
from report_generator.generator.context.portfolio_filters import (
    filter_data_on_portfolio_arguments,
)
from report_generator.generator.domain.portfolio.maintainability_portfolio import (
    maintainability_portfolio_data,
)


class SecurityPortfolioFindings:
    @cached_property
    @filter_data_on_portfolio_arguments(system_tag="systemName")
    def data(self):
        return [
            {"systemName": system_name, "findings": sigrid_api.get_security_findings(system_name)}
            for system_name in maintainability_portfolio_data.system_names
        ]

    @cached_property
    def findings(self):
        return list(chain.from_iterable(entry["findings"] for entry in self.data))

    def count_findings(self, severity: str) -> int:
        return sum(1 for finding in self.findings if finding["severity"] == severity)


security_findings_portfolio_data = SecurityPortfolioFindings()
