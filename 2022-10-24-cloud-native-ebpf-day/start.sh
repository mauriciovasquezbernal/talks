#! /bin/bash

set -x
set -e

# start cluster
# For Inspektor Gadget
#minikube start --nodes=2
# For traditional tools
minikube start --nodes=2 --driver=kvm #--iso-url=file://$(pwd)/minikube-fanotify.iso

# create container image
docker build -t mauriciovasquezbernal/mynginx:latest .

# load image for container
minikube image load mauriciovasquezbernal/mynginx:latest

# copy seccomp profiles
for NODE in minikube minikube-m02
do
	minikube ssh -n $NODE -- "sudo mkdir -p /var/lib/kubelet/seccomp/"
	minikube cp myseccompprofile.json $NODE:/var/lib/kubelet/seccomp/myseccompprofile.json
done

# TODO: deploy workload

for NODE in minikube minikube-m02
do
	for TOOL in opensnoop execsnoop tcptracer
	do
		minikube cp /home/mvb/kinvolk/ebpf/bcc/libbpf-tools/$TOOL $NODE:/home/docker/$TOOL
		minikube ssh -n $NODE -- "sudo chmod +x /home/docker/$TOOL"
	done
done

# Only for Docker driver
#for NODE in minikube minikube-m02
#do
#	minikube ssh -n $NODE -- "sudo apt-get update -y && sudo apt-get install vim -y"
#done
