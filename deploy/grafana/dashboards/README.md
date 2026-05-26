# Wicket Grafana Dashboards

Standalone Grafana dashboards for Wicket deployments that are not managed by Helm.

Import these JSON files directly in Grafana or provision them with Grafana's dashboard provisioning. Each dashboard has variables for:

- `datasource`: Prometheus datasource
- `job`: Prometheus scrape job selector, default `All`
- `instance`: Prometheus instance/server selector, default `All`

Dashboards:

- `wicket-proxy-core.json`: HTTP/L7 proxy fleet and per-server metrics
- `wicket-stream.json`: L4 stream proxy metrics
- `wicket-tls.json`: TLS and ACME health
- `wicket-controller.json`: Kubernetes controller health

For standalone CDN/proxy deployments, start with `wicket-proxy-core.json`, `wicket-stream.json`, and `wicket-tls.json`.
