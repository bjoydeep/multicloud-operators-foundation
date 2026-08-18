# Proxy Server Request Configuration

Proxy Server provides a serverless aggregated API `clusterstatus` to proxy requests from managed clusters to other backend servers. The API `clusterstatus` group is `proxy.open-cluster-management.io` and version is `v1beta1`

## clusterstatus/aggregator

Proxy Server provides sub resource under `clusterstatus/aggregator` for client agents on managed clusters to post data to hub.

For example, an agent named search in managed cluster wants to post data to its backend search service `<service-host>:<port>/search/cluster/<cluster-name>/<sub resource>/xxx`.
It can post data to `apis/proxy.open-cluster-management.io/v1beta1/namespaces/<cluster-namespace>/clusterstatuses/<cluster-name>/aggregator/<sub resource>/xxx`.
Proxy Server will proxy the requests to the backend search service who finally save the data.

### Configuration Example

User can configure the proxy information using a configMap with the label `config: acm-proxyserver`.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: search-proxy
  labels:
    config: acm-proxyserver
data:
  service: "kube-system/service-name"
  port: "8801"
  path: "/search/cluster/"
  sub-resource: "/searchdata"
  use-id: "true"
  secret: "kube-system/search-secret"
  caConfigMap: "kube-system/search-caCrt-configmap"
```

**data:**

* `service`: The backend service name, Format is `namespace/<service-name>`.
* `port`: The export port of the backend service.
* `path`: The path for agents to send requests.
* `sub-resource`: The resource of requests from agents.
* `use-id`: If true, the path of requests includes cluster name as ID. If false, there is no ID in the path.
* `secret`: The secret with signed serving certificate and key pair information to access the backend service. Format is `namespace/<secret-name>`.
* `caConfigMap`: The configmap with CA certificate information to access the backend service. Format is `namespace/<configMap-name>`.
## clusterstatus/log

Proxy Server provides sub resource under `clusterstatus/log` for clients to get logs of container on managed clusters.

For example, user can GET `apis/proxy.open-cluster-management.io/v1beta1/namespaces/cluster0/clusterstatuses/cluster0/log/multicloud-system/mongo-0/mongo` if we want to get logs of container `mongo` in pod `mongo-0` of namespace `default` in managed cluster `cluster0`.

## Debug Logging

The proxy server uses klog v2. To enable debug logging, add the `-v` flag to the container args in the Deployment.

### Verbosity Levels

| Flag | Detail |
|------|--------|
| `-v=0` | Errors and basic info (default) |
| `-v=2` | State changes and events |
| `-v=4` | Debug-level detail |
| `-v=8` | Very verbose / trace |

Use `-vmodule=<file>=<level>` to set verbosity per source file (e.g. `-vmodule=userpermission=4`).

### Pausing the MCE Operator

The `ocm-proxyserver` Deployment is managed by the MultiClusterEngine (MCE) operator
(upstream: [stolostron/backplane-operator](https://github.com/stolostron/backplane-operator)).
The operator will revert any manual changes to the Deployment on its next reconcile loop.

Before patching the Deployment, pause MCE reconciliation:

```bash
oc annotate multiclusterengine multiclusterengine \
  installer.multicluster.openshift.io/pause=true
```

To unpause after debugging:

```bash
oc annotate multiclusterengine multiclusterengine \
  installer.multicluster.openshift.io/pause-
```

### Enabling Debug Logging

With MCE paused, add `-v=4` to the container args in the `ocm-proxyserver` Deployment:

```yaml
args:
  - "/proxyserver"
  - "--secure-port=6443"
  - "--tls-cert-file=/var/run/apiservice/tls.crt"
  - "--tls-private-key-file=/var/run/apiservice/tls.key"
  - "--proxy-service-cafile=/var/run/clusterproxy/service-ca.crt"
  - "--proxy-service-name=cluster-proxy-addon-user"
  - "--proxy-service-port=9092"
  - "-v=4"
```

Or patch the Deployment directly:

```bash
oc -n multicluster-engine patch deployment ocm-proxyserver --type=json \
  -p '[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"-v=4"}]'
```

Then check the logs:

```bash
oc logs -f deployment/ocm-proxyserver -n multicluster-engine
```