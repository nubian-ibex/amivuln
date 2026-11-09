# Grafana dashboard

`amivuln.json` visualizes the metrics of `amivuln -f prometheus` collected through
the node_exporter textfile collector (see `contrib/systemd`). Import it from
Dashboards, New, Import, and choose your Prometheus data source.

It shows affected findings by severity, KEV membership, unverified findings,
per-source health and age, incomplete runs and stale scans. The dashboard
queries only the `amivuln_*` metrics.
