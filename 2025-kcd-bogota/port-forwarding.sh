#! /bin/bash

set -xe

kubectl port-forward --namespace monitoring deployment/prometheus 9090:9090 &

export POD_NAME=$(kubectl get pods --namespace monitoring -l "app.kubernetes.io/name=grafana,app.kubernetes.io/instance=grafana" -o jsonpath="{.items[0].metadata.name}")
kubectl --namespace monitoring port-forward $POD_NAME 3000 &
