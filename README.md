Tetragon Process Execution Sidecar
==================================

A Kubernetes sidecar for filtering, logging and guaging Tetragon process execution events.

## Configuration

```yaml
rules:
  # This rule will log all process exec events in the default namespace
  # for containers named "nginx", excluding events from the nginx binary.
  nginx-exec:
    namespaces:
      - default
    containers:
      - nginx
    labels:
      app: webserver
    excludeBinaries:
      - /usr/sbin/nginx
```
