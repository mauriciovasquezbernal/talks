#! /bin/bash

helm uninstall tetragon -n kube-system
helm repo remove cilium

kubectl delete -f prometheus.yaml
