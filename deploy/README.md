# Wicket k3d POC - Deployment Guide

This guide walks through deploying Wicket to a local k3d Kubernetes cluster for testing and development.

## Prerequisites

Install the following tools:

- **k3d** (v5.0+): Lightweight Kubernetes in Docker
  ```bash
  curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash
  ```

- **kubectl** (v1.24+): Kubernetes CLI
  ```bash
  # macOS
  brew install kubectl
  
  # Linux
  curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
  chmod +x kubectl && sudo mv kubectl /usr/local/bin/
  ```

- **Docker**: Container runtime (required by k3d)
  ```bash
  # macOS
  brew install docker
  # or download Docker Desktop
  
  # Linux
  curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh
  ```

Verify installations:
```bash
k3d version
kubectl version --client
docker --version
```

## Quick Start

### 1. Create the k3d Cluster

```bash
k3d cluster create -c deploy/k3d/cluster.yaml
```

This creates a cluster named `wicket-poc` with:
- 1 server (control plane)
- 2 agents (worker nodes)
- Port 8080 mapped to localhost for testing

Verify the cluster is running:
```bash
kubectl cluster-info
kubectl get nodes
```

### 2. Build and Push the Wicket Image

Build the Docker image:
```bash
docker build -t wicket:latest .
```

Import the image into k3d (no registry needed for local testing):
```bash
k3d image import wicket:latest -c wicket-poc
```

### 3. Apply Kubernetes Manifests

Create the namespace and deploy services:
```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/echo.yaml
kubectl apply -f deploy/k8s/httpbin.yaml
kubectl apply -f deploy/k8s/wicket.yaml
kubectl apply -f deploy/k8s/wicket-config.yaml
```

Verify deployments:
```bash
kubectl get pods -n wicket-poc
kubectl get svc -n wicket-poc
```

Wait for all pods to be ready:
```bash
kubectl wait --for=condition=ready pod -l app=wicket -n wicket-poc --timeout=300s
```

### 4. Run Integration Tests

```bash
./deploy/test.sh
```

The test script will:
- Wait for all pods to be ready
- Test routing to echo and httpbin services
- Verify load balancing across echo replicas
- Print colored pass/fail results

Expected output:
```
==========================================
Wicket k3d POC - Integration Tests
==========================================

[INFO] Waiting for all pods to be ready (timeout: 300s)...
[PASS] All pods are ready (5/5)

[INFO] Testing routing...
[INFO]   Test 1: GET / → echo
[PASS]    Root path routed to echo (HTTP 200)
[INFO]   Test 2: GET /echo/test → echo
[PASS]    /echo/test routed to echo (HTTP 200)
[INFO]   Test 3: GET /api/get → httpbin
[PASS]    /api/get routed to httpbin (HTTP 200)

Routing: 3 passed, 0 failed

[INFO] Testing load balancing...
[INFO]   Sending 10 requests to /echo...
[PASS]   Responses from 2 pod(s):
    echo-abc123: 5 hits
    echo-def456: 5 hits
[PASS]   Load balancing is working (requests distributed across pods)

==========================================
[PASS] All tests passed!
==========================================
```

## Cleanup

Delete the cluster:
```bash
k3d cluster delete wicket-poc
```

This removes all pods, services, and the cluster itself.

## Troubleshooting

### Cluster Creation Fails

**Error**: `Error: failed to create cluster`

**Solution**: 
- Ensure Docker is running: `docker ps`
- Check disk space: `df -h`
- Try deleting any existing cluster: `k3d cluster delete wicket-poc`

### Pods Not Starting

**Error**: `ImagePullBackOff` or `CrashLoopBackOff`

**Solution**:
- Verify image was imported: `k3d image list -c wicket-poc`
- Check pod logs: `kubectl logs -n wicket-poc <pod-name>`
- Ensure image tag matches manifest: `grep image deploy/k8s/wicket.yaml`

### Port 8080 Already in Use

**Error**: `Error: failed to bind port 8080`

**Solution**:
- Find process using port: `lsof -i :8080`
- Kill process: `kill -9 <PID>`
- Or use different port in `k3d/cluster.yaml`: change `8080:8080` to `8081:8080`

### Tests Fail - Connection Refused

**Error**: `curl: (7) Failed to connect to localhost port 8080`

**Solution**:
- Verify port mapping: `k3d cluster list`
- Check wicket pod is running: `kubectl get pods -n wicket-poc`
- View wicket logs: `kubectl logs -n wicket-poc -l app=wicket`
- Ensure manifests were applied: `kubectl get all -n wicket-poc`

### Tests Fail - Routing Not Working

**Error**: `[FAIL] Root path failed (HTTP 404)`

**Solution**:
- Check wicket config: `kubectl get configmap -n wicket-poc wicket-config -o yaml`
- Verify routes are defined in `wicket.toml`
- Check upstream services are running: `kubectl get svc -n wicket-poc`
- View wicket logs for routing errors: `kubectl logs -n wicket-poc -l app=wicket --tail=50`

### Load Balancing Not Working

**Error**: `[FAIL] Load balancing not working (all requests hit same pod)`

**Solution**:
- Verify echo has multiple replicas: `kubectl get pods -n wicket-poc -l app=echo`
- Check service endpoints: `kubectl get endpoints -n wicket-poc echo`
- Ensure wicket is configured to load balance (check `wicket.toml`)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      k3d Cluster                            │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                  Kubernetes Nodes                    │  │
│  │                                                      │  │
│  │  ┌─────────────────┐  ┌─────────────────────────┐  │  │
│  │  │  Control Plane  │  │   Worker Nodes (x2)     │  │  │
│  │  │                 │  │                         │  │  │
│  │  │  API Server     │  │  ┌─────────────────┐   │  │  │
│  │  │  etcd           │  │  │ Wicket Pod      │   │  │  │
│  │  │  Scheduler      │  │  │ (Reverse Proxy) │   │  │  │
│  │  │                 │  │  └─────────────────┘   │  │  │
│  │  └─────────────────┘  │                         │  │  │
│  │                       │  ┌─────────────────┐   │  │  │
│  │                       │  │ Echo Pod (x2)   │   │  │  │
│  │                       │  │ (Test Service)  │   │  │  │
│  │                       │  └─────────────────┘   │  │  │
│  │                       │                         │  │  │
│  │                       │  ┌─────────────────┐   │  │  │
│  │                       │  │ HTTPBin Pod     │   │  │  │
│  │                       │  │ (Test Service)  │   │  │  │
│  │                       │  └─────────────────┘   │  │  │
│  │                       └─────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  Port Mapping:                                              │
│  localhost:8080 ──────────────────> Wicket Service         │
└─────────────────────────────────────────────────────────────┘

Request Flow:
  curl localhost:8080/
    ↓
  Wicket (Reverse Proxy)
    ├─ Route: / → Echo Service
    ├─ Route: /echo/* → Echo Service
    └─ Route: /api/* → HTTPBin Service
    ↓
  Backend Service (Echo or HTTPBin)
    ↓
  Response
```

## Configuration

### Wicket Routes

Routes are defined in `wicket.toml` and mounted as a ConfigMap:

```toml
[upstreams.echo]
backends = ["echo-svc.wicket-poc.svc.cluster.local:80"]

[upstreams.httpbin]
backends = ["httpbin-svc.wicket-poc.svc.cluster.local:80"]

[[routes]]
name = "echo-route"
upstream = "echo"
[routes.match]
path_prefix = "/echo"

[[routes]]
name = "api-route"
upstream = "httpbin"
[routes.match]
path_prefix = "/api"

[[routes]]
name = "default-route"
upstream = "echo"
[routes.match]
path_prefix = "/"
```

## Development Workflow

### Local Testing

1. Make changes to Wicket code
2. Rebuild image: `docker build -t wicket:latest .`
3. Reimport to k3d: `k3d image import wicket:latest -c wicket-poc`
4. Restart pod: `kubectl rollout restart deployment/wicket -n wicket-poc`
5. Run tests: `./deploy/test.sh`

### Viewing Logs

```bash
# Wicket logs
kubectl logs -n wicket-poc -l app=wicket -f

# Echo logs
kubectl logs -n wicket-poc -l app=echo -f

# All logs
kubectl logs -n wicket-poc -f --all-containers=true
```

### Port Forwarding

Forward a service to localhost for direct testing:

```bash
# Forward wicket service
kubectl port-forward -n wicket-poc svc/wicket 8080:8080

# Forward echo service
kubectl port-forward -n wicket-poc svc/echo 8081:8080
```

### Debugging

Exec into a pod:

```bash
kubectl exec -it -n wicket-poc <pod-name> -- /bin/sh
```

Describe pod for events:

```bash
kubectl describe pod -n wicket-poc <pod-name>
```

## Next Steps

- Modify `wicket.toml` to test different routing rules
- Scale echo replicas: `kubectl scale deployment echo -n wicket --replicas=3`
- Add new test services to `deploy/k8s/`
- Implement TLS/HTTPS testing
- Add performance benchmarking to `test.sh`
