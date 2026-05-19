import csv
import gzip
import io
import urllib.request

_epss_scores_cache: dict[str, float] | None = None


def _fetch_epss_scores() -> dict[str, float]:
    global _epss_scores_cache
    if _epss_scores_cache is not None:
        return _epss_scores_cache

    url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    with urllib.request.urlopen(url) as response:
        compressed = response.read()

    with gzip.open(io.BytesIO(compressed), "rt") as f:
        f.readline()  # skip comment line: #model_version:...,score_date:...
        reader = csv.DictReader(f)
        _epss_scores_cache = {row["cve"]: float(row["epss"]) for row in reader}

    return _epss_scores_cache


def enrich_cves_with_epss_scores(cves: dict) -> None:
    epss_scores = _fetch_epss_scores()
    for cve_id, data in cves.items():
        data["epss-score"] = epss_scores.get(cve_id)


def exploit_probability(cves: dict) -> float:
    product = 1.0
    for data in cves.values():
        if data["epss-score"] is not None:
            product *= (1 - data["epss-score"]) ** data["count"]
    return min(1 - product, 0.9999)


def aggregate_cves_across_systems(cves_per_system: dict) -> dict:
    result: dict = {}
    for system_cves in cves_per_system.values():
        if not system_cves:
            continue
        for cve, data in system_cves.items():
            if cve not in result:
                result[cve] = {"count": 0}
            result[cve]["count"] += data["count"]
    return result
