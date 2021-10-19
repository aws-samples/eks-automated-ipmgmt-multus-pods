
## Automated Multus pod IP management on EKS

For multus pods on EKS, primary pod interface is managed by VPC CNI, however secondary interfaces are managed by other CNIs like ipvlan and different ipams like "host-local" , "static" or "whereabouts" via multus meta-plugin. To make these secondary interfaces IPs routable in VPC network, the IP allocation needs to be done manually on the worker node ENS handling the master interface for the multus network attachment. This blog explains the procedure of automating this IP allocation seamlessly, without any change in application code.   

### Problem:
VPC provides Layer 3 networking, which means only IP address can be used to communicate with one another, Besides that It also maintains coupling of MAC and associated IP addresses to route the traffic to correct ENI (Elastic Network interface), Each ENI attached to EC2 Worker node, needs to have the desired IP address(es) assigned to it.
Since, Multus pods are using ipvlan CNI, which means that the macaddress of the pod remains same as the master interface (In this example its eth1). However, vpc will not be aware of the assumed IP address of the pod, since the IP allocations to these pods hasn’t happened via VPC. VPC is only aware of the IP addresses allocated on the ENI on EC2 worker nodes.
Note: This can be verified on the EC2 console → Instances→ Select Instance (worker)→ Actions → Networking → Manage IP Addresses. You wouldnt see the multus secondary pod IP adresses on the ENI.

### Automated solution:
Assignment of the can be automated by using assign ip address/unassign ip address API calls on the worker node ENIs.  
The python code and script in the "code" directory on this repo can achieve the same. This automation can be managed and still be done by without modifying the application image or adding any additional source code change. We can leverage the flexible container architecture of a kubernetes pod and get this solved by utilizing an “ip management container”. This special container can perform the automation of the IP allocation on the respective worker Node ENIs, without any impact on applications containers or its architecture. We can just enhance the spec of the workload pod/deployment/statefulset with this additional container.

#### Pre-requisite

1. EKS cluster
2. Self managed nodegroup (minimum 2 workers) with secondary ENIs 
3. Security group on the worker nodes have ICMP traffic allowed between worker nodes
4. multus CNI (along with ipvlan CNI) 
5. whereabouts IPAM CNI

#### How to Build

Clone this repo:

```
git clone https://github.com/aws-samples/eks-automated-ipmgmt-multus-pods
```
Please replace the xxxxxxxxx with your accout id and also choose the region where your ECR repository is.


```
docker build --tag xxxxxxxxx.dkr.ecr.us-east-2.amazonaws.com/aws-ip-manager:0.1 .
aws ecr get-login-password --region us-east-2 | docker login --username AWS --password-stdin xxxxxxxxx.dkr.ecr.us-east-2.amazonaws.com
aws ecr create-repository --repository-name aws-ip-manager --region us-east-2
docker push xxxxxxxxx.dkr.ecr.us-east-2.amazonaws.com/aws-ip-manager:0.1
```

####  Option 1: InitContainer IP management Solution

This is a simple solution and works for most of the ipvlan CNI pods, which don’t have a special/custom handling like floating IP etc. (explained in next option). This solution doesn’t add a constraint of additional cpu/memory requirement on the worker.
In this solution as the name suggests the “ip management container” is deployed as initContainer of the kubernetes workload. This container would be executed as first container while the POD is in init mode.  This container will check the ip address of the pod (ip a command) & allocate the multus ip addresses to the ENI, while the pod is in init state. Once the multus IP addresses are successfully assigned to the worker node ENIs, this initContainer will terminate and pod will come out of the init state. All other containers will start coming up and would be ready to serve traffic, as IP assignment has already taken place. Whenever a pod restarts or gets deployed on a new worker node, the entire life cycle of the pod repeats, including the initContainer, thereby taking care of the IP address assignment on the respective ENI.

To use this option, we need to add this snippet in your workloads (use your account number in place of xxxxxxxxx), whether its a simple pod, daemonset or any replicaset based workload (deployment or statefulset).

      initContainers:
      - name: aws-ip-mgmt
        image: xxxxxxxxx.dkr.ecr.us-east-2.amazonaws.com/aws-ip-manager:0.1
        imagePullPolicy: IfNotPresent
        args: [/bin/sh, -c, '/app/script.sh initContainers']  

Deploy the sample pod for initContainer in samples direcory, use your account number in place of xxxxxxxxx, and test it. 
```
$ kubectl create ns multus
namespace/multus created
$ kubectl apply -f multus-nad-wb.yaml
networkattachmentdefinition.k8s.cni.cncf.io/ipvlan-multus created
$ kubectl apply -f busybox-deployment-initContainer.yaml
deployment.apps/busybox-deployment created
$ kubectl -n multus get po -o wide
NAME                                  READY   STATUS    RESTARTS   AGE   IP             NODE                                         NOMINATED NODE   READINESS GATES
busybox-deployment-7676bf4bb7-45f7z   1/1     Running   0          19s   10.10.12.12    ip-10-10-12-248.us-east-2.compute.internal   <none>           <none>
busybox-deployment-7676bf4bb7-b7jv4   1/1     Running   0          19s   10.10.12.219   ip-10-10-12-37.us-east-2.compute.internal    <none>           <none>
busybox-deployment-7676bf4bb7-q2wgr   1/1     Running   0          19s   10.10.12.207   ip-10-10-12-248.us-east-2.compute.internal   <none>           <none>
$ kubectl -n multus exec -it busybox-deployment-7676bf4bb7-45f7z  -- ip a | grep -B1 "global net1"
    link/ether 02:e2:16:d5:f8:26 brd ff:ff:ff:ff:ff:ff
    inet 10.10.1.81/24 brd 10.10.1.255 scope global net1
$ kubectl -n multus exec -it busybox-deployment-7676bf4bb7-b7jv4  -- ip a | grep -B1 "global net1"
    link/ether 02:a0:3c:01:bb:76 brd ff:ff:ff:ff:ff:ff
    inet 10.10.1.80/24 brd 10.10.1.255 scope global net1
$ kubectl -n multus exec -it busybox-deployment-7676bf4bb7-q2wgr  -- ip a | grep -B1 "global net1"
    link/ether 02:e2:16:d5:f8:26 brd ff:ff:ff:ff:ff:ff
    inet 10.10.1.82/24 brd 10.10.1.255 scope global net1
$
$ kubectl -n multus exec -it busybox-deployment-7676bf4bb7-q2wgr  -- ping -c 1 10.10.1.80
PING 10.10.1.80 (10.10.1.80): 56 data bytes
64 bytes from 10.10.1.80: seq=0 ttl=255 time=0.236 ms

--- 10.10.1.80 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 0.236/0.236/0.236 ms
$ kubectl -n multus exec -it busybox-deployment-7676bf4bb7-q2wgr  -- ping -c 1 10.10.1.81
PING 10.10.1.81 (10.10.1.81): 56 data bytes
64 bytes from 10.10.1.81: seq=0 ttl=255 time=0.043 ms

--- 10.10.1.81 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 0.043/0.043/0.043 ms
$
```
#### Option 2: Sidecar IP management Solution

Sidecar IP management container, as the name indicates, will be running as an additional or sidecar container and unlike the initContainer, it keeps on monitoring the pod for new or change in ip addresses and if there is any update/change noticed, it will assign the IPs to the ENI, thereby minimizing the traffic impact. This is very helpful, when the pod has some custom handling, where the IP address can change or it has a handing of “Floating IP”/“Virtual IP”. A usecase could be, where the pods are running in active/standby mode and, if a pod crashes or has any issues, the “Floating IP”/“Virtual IP” address can fail over to other pod, without any traffic disruption and maintaining the single-entry point.

In this case the sidecar keeps running and monitoring the pod, so there is additional usage of the CPU/Memory (minimal) of this container, per multus based pods. (use your account number in place of xxxxxxxxx) in below example

      containers:
      - name: aws-ip-mgmt
        image: xxxxxx.dkr.ecr.us-east-2.amazonaws.com/aws-ip-manager:0.1
        imagePullPolicy: Always
        args: [/bin/sh, -c, '/app/script.sh sidecar']

Deploy the sample pod for sidecar solutions in samples direcory,use your account number in place of xxxxxxxxx and test it
```
$ kubectl create ns multus
namespace/multus created
$ kubectl apply -f multus-nad-wb.yaml
networkattachmentdefinition.k8s.cni.cncf.io/ipvlan-multus created
$ kubectl apply -f busybox-deployment-sidecar.yaml
deployment.apps/busybox-deployment created
$ kubectl -n multus get po -o wide
NAME                                 READY   STATUS    RESTARTS   AGE   IP             NODE                                         NOMINATED NODE   READINESS GATES
busybox-deployment-b96855685-748s4   2/2     Running   0          37s   10.10.12.200   ip-10-10-12-37.us-east-2.compute.internal    <none>           <none>
busybox-deployment-b96855685-bk8pm   2/2     Running   0          37s   10.10.12.199   ip-10-10-12-37.us-east-2.compute.internal    <none>           <none>
busybox-deployment-b96855685-llg6n   2/2     Running   0          37s   10.10.12.130   ip-10-10-12-248.us-east-2.compute.internal   <none>           <none>
$
$ kubectl -n multus exec -it busybox-deployment-b96855685-748s4 -- ip a | grep -B1 "global net1"
Defaulting container name to busybox.
Use 'kubectl describe pod/busybox-deployment-b96855685-748s4 -n multus' to see all of the containers in this pod.
    link/ether 02:a0:3c:01:bb:76 brd ff:ff:ff:ff:ff:ff
    inet 10.10.1.80/24 brd 10.10.1.255 scope global net1
$ kubectl -n multus exec -it busybox-deployment-b96855685-bk8pm -- ip a | grep -B1 "global net1"
Defaulting container name to busybox.
Use 'kubectl describe pod/busybox-deployment-b96855685-bk8pm -n multus' to see all of the containers in this pod.
    link/ether 02:a0:3c:01:bb:76 brd ff:ff:ff:ff:ff:ff
    inet 10.10.1.81/24 brd 10.10.1.255 scope global net1
$ kubectl -n multus exec -it busybox-deployment-b96855685-llg6n -- ip a | grep -B1 "global net1"
Defaulting container name to busybox.
Use 'kubectl describe pod/busybox-deployment-b96855685-llg6n -n multus' to see all of the containers in this pod.
    link/ether 02:e2:16:d5:f8:26 brd ff:ff:ff:ff:ff:ff
    inet 10.10.1.82/24 brd 10.10.1.255 scope global net1
$ kubectl -n multus exec -it busybox-deployment-b96855685-llg6n -- ping -c1 10.10.1.80
Defaulting container name to busybox.
Use 'kubectl describe pod/busybox-deployment-b96855685-llg6n -n multus' to see all of the containers in this pod.
PING 10.10.1.80 (10.10.1.80): 56 data bytes
64 bytes from 10.10.1.80: seq=0 ttl=255 time=0.212 ms

--- 10.10.1.80 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 0.212/0.212/0.212 ms
[ec2-user@ip-10-10-10-48 busybox]$ kubectl -n multus exec -it busybox-deployment-b96855685-llg6n -- ping -c1 10.10.1.81
Defaulting container name to busybox.
Use 'kubectl describe pod/busybox-deployment-b96855685-llg6n -n multus' to see all of the containers in this pod.
PING 10.10.1.81 (10.10.1.81): 56 data bytes
64 bytes from 10.10.1.81: seq=0 ttl=255 time=0.209 ms

--- 10.10.1.81 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 0.209/0.209/0.209 ms
$
```
## Cleanup
```
$ kubectl create ns multus
$ kubectl delete -f busybox-deployment-sidecar.yaml
$ kubectl delete -f busybox-deployment-initContainer.yaml
$ kubectl delete -f multus-nad-wb.yaml
$ kubectl delete ns multus
```
## Conclusion

In this blog post, we covered how mulltus pods work in EKS and VPC scope. We demonstrated the deployment of multus based pods and discussed in detail, how IP allocation of these pods works and how they interact with Worker  and VPC networking. This blog only demonstrated the IPv4 handling, however in similar way, IPv6 handling is also present in the sample code.  

This solution might not be applicable for all the use cases or application requirements, so this code or the process shall be considered as sample  and can be enhanced/adapted per the different unique application architecture and use cases. 

Note: Thanks to my ex-colleague Neb Miljanovic,  who worked with me in developing this solution. 

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
