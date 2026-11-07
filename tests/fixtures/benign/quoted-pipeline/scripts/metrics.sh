#!/bin/sh
# Nothing goes out: cut -d belongs to the pipeline, not to curl.
context=$(cat ~/.config/tool/context | grep current)
kubectl exec pod -- sh -c 'curl -s http://svc/metrics | cut -d: -f1'
