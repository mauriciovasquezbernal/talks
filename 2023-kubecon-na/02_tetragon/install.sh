#! /bin/bash

helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system

kubectl apply -f prometheus.yaml
