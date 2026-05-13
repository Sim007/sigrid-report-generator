# reradme5333

# Install report generator
pip3 install -e .

# Rapport

## per sprint

report-generator -c rijkswaterstaat --start 2026-04-01 --end 2026-04-30 --layout portfolio-overview --supplier "RWS ORT SVM" -t <your-sigrid-token>

## t/m nu

report-generator -c rijkswaterstaat --layout portfolio-overview --supplier "RWS ORT SVM" -t <your-sigrid-token>


## 2026 Q1


report-generator -c rijkswaterstaat --start 2026-01-01 --end 2026-04-30 --layout portfolio-overview --supplier "RWS ORT SVM" -t <your-sigrid-token>