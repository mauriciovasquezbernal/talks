#! /bin/bash

# another idea: Remove the video file from one of the pods
#PODNAME=$(kubectl get pods --selector=app=myapp --output=jsonpath={.items[0].metadata.name})
#kubectl exec $PODNAME -- rm /usr/share/nginx/html/video.mp4

# first of all create a backup
cp mydeployment.yaml mydeployment.yaml.backup

# use a bad seccomp profile in one node
minikube cp myseccompprofile_bad.json minikube-m02:/var/lib/kubelet/seccomp/myseccompprofile.json

# remove a needed capability
sed -i 's#              - NET_BIND_SERVICE##g' mydeployment.yaml

# use bad port in the service
sed -i 's#targetPort: 777#targetPort: 888#g' mydeployment.yaml

kubectl delete -f mydeployment.yaml
kubectl apply -f mydeployment.yaml
