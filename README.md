# openshift-workshop

## Project Title

Day 2 Operations for Openshift 3

## Disclaimer

**This is a reference manual for day 2 operations on Openshift 3 for didactic use only so it is not expected to use it for production environments.** 
**Please use the latest official documentation instead for production usage. Changes in the procedures can appear on each specific release.**

https://docs.openshift.com/container-platform/3.11/welcome/index.html   

<br><br>
## Openshift 3 Architecture

The following workshop applies for a test Openshift 3.11 cluster using OCS 3.11 with gluster in independent mode.

![alt text]( images/arch-independent.png "Architecture")  

<br><br>
## Openshift 3 Upgrade

### Official Documentation

https://docs.openshift.com/container-platform/3.11/upgrading/index.html#install-config-upgrading-strategy-inplace

* Make sure that you have a full backup of the cluster before upgrading it.

* Update ansible playbooks to the desired version that we want to upgrade (latest) on bastion host.

```bash
$ yum update -y openshift-ansible
$ rpm -q openshift-ansible
Openshift-ansible-3.11.x
```

* Modify cluster inventory in order to reflect the new package and image versions.

```bash
$ cat hosts
openshift_pkg_version="-3.11.82"
openshift_image_tag="v3.11.82"
...
openshift_metrics_image_version=v3.11.82
openshift_logging_image_version=v3.11.82
openshift_service_catalog_image_version=v3.11.82
...
openshift_web_console_version="v3.11.82"
openshift_console_image_name=registry.redhat.io/openshift3/ose-console:v3.11.82
```
Change 3.11.82 to 3.11.117 for example

* From bastion node, upgrade the control plane.

```bash
$ cd /usr/share/ansible/openshift-ansible && ansible-playbook -i hosts playbooks/byo/openshift-cluster/upgrades/v3_11/upgrade_control_plane.yml
```

* From bastion node, upgrade infra nodes.

```bash
$ cd /usr/share/ansible/openshift-ansible && ansible-playbook -i hosts playbooks/byo/openshift-cluster/upgrades/v3_11/upgrade_nodes.yml -e openshift_upgrade_nodes_label="node-role.kubernetes.io/infra=true"
```

* From bastion node, upgrade worker nodes.

```bash
$ cd /usr/share/ansible/openshift-ansible && ansible-playbook -i hosts playbooks/byo/openshift-cluster/upgrades/v3_11/upgrade_nodes.yml -e openshift_upgrade_nodes_label="node-role.kubernetes.io/compute=true"
```

* Quick upgrade verify.

```bash
$ oc get nodes
$ oc get pods -n kube-system
$ oc get pods --all-namespaces
$ oc get pvc --all-namespaces
$ oc get pv
$ oc get -n default dc/docker-registry -o json | grep \"image\"
    "image": "openshift3/ose-docker-registry:v3.11.117",
$ oc get -n default dc/router -o json | grep \"image\"
    "image": "openshift3/ose-haproxy-router:v3.11.117",
```

* Run Openshift 3 HealthCheck procedure (see next section).


<br><br>
## Openshift 3 HealthCheck

### Official Documentation

https://docs.openshift.com/container-platform/3.11/day_two_guide/environment_health_checks.html
https://docs.openshift.com/container-platform/3.11/admin_guide/diagnostics_tool.html
https://access.redhat.com/documentation/en-us/openshift_container_platform/3.11/html-single/day_two_operations_guide/#day-two-guide-network-connectivity

### Ansible-based Health Checks

Health checks are available through the Ansible-based tooling used to install and manage OpenShift Container Platform clusters. They can report common deployment problems for the current OpenShift Container Platform installation.

```bash
$ cd /usr/share/ansible/openshift-ansible && ansible-playbook -i hosts -e openshift_disable_check=curator,elasticsearch,logging_index_time,diagnostics playbooks/openshift-checks/health.yml
```

### Checking complete environment health - Deploy test app

```bash
$ oc new-project httpd-test
$ oc new-app --image-stream=httpd-24-rhel7
$ oc expose service httpd-24-rhel7
$ oc create route edge httpd-24-rhel7-ssl --service=httpd-24-rhel7 --hostname=httpd-24-rhel7-ssl-httpd-test.apps.info.net
$ oc get pods
$ oc get svc
$ oc get route

$ curl httpd-24-rhel7-httpd-test.apps.info.net
$ curl -k httpd-24-rhel7-httpd-test.apps.info.net
$ firefox httpd-24-rhel7-httpd-test.apps.info.net

$ oc delete project httpd-test
```

### Host health

```bash
master$ oc get nodes
master$ oc get pod --all-namespaces -o wide

master$ source /etc/etcd/etcd.conf
master$ etcdctl --cert-file=$ETCD_PEER_CERT_FILE --key-file=$ETCD_PEER_KEY_FILE \
  --ca-file=/etc/etcd/ca.crt --endpoints=$ETCD_LISTEN_CLIENT_URLS cluster-health
master$ etcdctl --cert-file=$ETCD_PEER_CERT_FILE --key-file=$ETCD_PEER_KEY_FILE \
  --ca-file=/etc/etcd/ca.crt --endpoints=$ETCD_LISTEN_CLIENT_URLS member list
```


### Router and registry health

```bash
$ oc -n default get deploymentconfigs/router
NAME      REVISION   DESIRED   CURRENT   TRIGGERED BY
router    1          3         3         config


$ oc -n default get deploymentconfigs/docker-registry
NAME              REVISION   DESIRED   CURRENT   TRIGGERED BY
docker-registry   1          3         3         config

* The values in the DESIRED and CURRENT columns should match the number of nodes hosts *
```

### Network connectivity

#### Connectivity on master hosts

Master services keep their state synchronized using the etcd key-value store. This communication happens on TCP ports 2379 and 2380.


```bash
$ oc get nodes
...
```
(Ready status means that master hosts can communicate with node hosts and that the nodes are ready to run pods (excluding the nodes in which scheduling is disabled))


#### SkyDNS

SkyDNS provides name resolution of local services running in OpenShift Container Platform. This service uses TCP and UDP port 8053.

```bash
$ dig +short docker-registry.default.svc.cluster.local
172.30.150.7

$ oc get svc/docker-registry -n default
NAME              CLUSTER-IP     EXTERNAL-IP   PORT(S)    AGE
docker-registry   172.30.150.7   <none>        5000/TCP   3d
```

-> 172.30.150.7 equivalent IP match


#### API service and web console

Both the API service and web console share the same port, usually TCP 8443 or 443, depending on the setup. This port needs to be available within the cluster and to everyone who needs to work with the deployed environment.


```bash
$ curl -k https://loadbalancer.2e5b.example.opentlc.com:443/version
{
  "major": "1",
  "minor": "6",
  "gitVersion": "v1.6.1+5115d708d7",
  "gitCommit": "fff65cf",
  "gitTreeState": "clean",
  "buildDate": "2017-10-11T22:44:25Z",
  "goVersion": "go1.7.6",
  "compiler": "gc",
  "platform": "linux/amd64"
}

$ curl -k https://loadbalancer.2e5b.example.opentlc.com:443/healthz
ok
```

#### Connectivity on node instances

The SDN connecting pod communication on nodes uses UDP port 4789 by default. To verify node host functionality, create a new application:

```bash
$ oc new-project sdn-test
$ oc new-app httpd~https://github.com/sclorg/httpd-ex
$ oc get pods

$ oc rsh po/<pod-name>
$ curl -kv https://docker-registry.default.svc.cluster.local:5000/healthz
* About to connect() to docker-registry.default.svc.cluster.locl port 5000 (#0)
*   Trying 172.30.150.7...
* Connected to docker-registry.default.svc.cluster.local (172.30.150.7) port 5000 (#0)
* Initializing NSS with certpath: sql:/etc/pki/nssdb
* skipping SSL peer certificate verification
* SSL connection using TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
* Server certificate:
*       subject: CN=172.30.150.7
*       start date: Nov 30 17:21:51 2017 GMT
*       expire date: Nov 30 17:21:52 2019 GMT
*       common name: 172.30.150.7
*       issuer: CN=openshift-signer@1512059618
> GET /healthz HTTP/1.1
> User-Agent: curl/7.29.0
> Host: docker-registry.default.svc.cluster.local:5000
> Accept: */*
>
< HTTP/1.1 200 OK
< Cache-Control: no-cache
< Date: Mon, 04 Dec 2017 16:26:49 GMT
< Content-Length: 0
< Content-Type: text/plain; charset=utf-8
<
* Connection #0 to host docker-registry.default.svc.cluster.local left intact

sh-4.2$ *exit*

```
-> The HTTP/1.1 200 OK response means the node is correctly connecting.

```bash
$ oc delete project sdn-test
project "sdn-test" deleted
```

* To verify the functionality of the routers, check the registry service once more, but this time from outside the cluster:
-> Check external access to SDN

```bash
$ curl -kv https://docker-registry-default.apps.example.com/healthz
*   Trying 35.xx.xx.92...
* TCP_NODELAY set
* Connected to docker-registry-default.apps.example.com (35.xx.xx.92) port 443 (#0)
...
< HTTP/2 200
```

### DNS

Verify wilcard DNS points to LB.

```bash
$ dig *.apps.2e5b.example.opentlc.com
```

Verify all nodes have direct and inverse resolution.

```bash
$ ansible -i hosts all -m shell -a 'host $(hostname); host $(ip a | grep "inet 10." | awk  "{print \$2}" | cut -d/ -f1)' -u quicklab -b
```

### Storage

#### Nodes free space

Master instances need at least 40 GB of hard disk space for the /var directory. Check the disk usage of a master host using the df command:

```bash
$ ansible -i hosts -m shell -a "df -hT"
```

#### Check Heketi OCS status

Run the following script in one master and review the result:

```bash
master$ cat heketi-ocs-status.sh 
#!/bin/bash

STORAGE_PROJECT=$1

subscription-manager repos --enable="rh-gluster-3-client-for-rhel-7-server-rpms"
yum -y install heketi-client
subscription-manager repos --disable="rh-gluster-3-client-for-rhel-7-server-rpms"

oc project ${STORAGE_PROJECT}
export HEKETI_POD=$(oc get pods -l glusterfs=heketi-storage-pod -n ${STORAGE_PROJECT} -o jsonpath="{.items[0].metadata.name}")
export HEKETI_CLI_USER=admin
export HEKETI_CLI_KEY=$(oc get pod/$HEKETI_POD -n ${STORAGE_PROJECT} -o jsonpath='{.spec.containers[0].env[?(@.name=="HEKETI_ADMIN_KEY")].value}')
export HEKETI_ADMIN_KEY_SECRET=$( echo -n ${HEKETI_CLI_KEY} | base64 )
export HEKETI_CLI_SERVER=http://heketi-storage.${STORAGE_PROJECT}.svc:8080
curl -w '\n' ${HEKETI_CLI_SERVER}/hello
sleep 5

heketi-cli topology info
sleep 5

heketi-cli cluster list
heketi-cli node list
heketi-cli volume list
sleep 5

heketi-cli db check
sleep 5

heketi-cli server state examine gluster
sleep 5

master$ heketi-ocs-status.sh glusterfs 
...
``` 

#### Checking the default storage class

For proper functionality of dynamically provisioned persistent storage, the default storage class needs to be defined.

```bash
# oc get storageclass

# oc get sc
NAME                          PROVISIONER                AGE
glusterfs-storage (default)   kubernetes.io/glusterfs    1d
glusterfs-storage-block       gluster.org/glusterblock   1d
```

At least on storage class must be configured as default


#### Checking PVC and PV

Check all PVC are bond to a PV.

```bash
$ oc get pv
$ oc get pvc --all-namespaces
```


#### Checking PVC and use it on APP

```bash
$ oc new-project testme

$ cat pvc.yml
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
 name: claim1
 annotations:
   volume.beta.kubernetes.io/storage-class: glusterfs-storage
spec:
 accessModes:
   - ReadWriteOnce
 resources:
   requests:
     storage: 1Gi

$ oc create -f pvc.yml
$ oc get pvc -> BOUND

$ cat app.yml
apiVersion: v1
kind: Pod
metadata:
 name: busybox
spec:
 containers:
   - image: busybox
     command:
       - sleep
       - "3600"
     name: busybox
     volumeMounts:
       - mountPath: /usr/share/busybox
         name: mypvc
 volumes:
   - name: mypvc
     persistentVolumeClaim:
       claimName: claim1


$ oc create -f app.yml
$ oc describe pod busybox  -> Observe Mount
$ oc get pvc
$ oc get pv
$ oc get events
```

### Docker storage

Docker storage disk is mounted as /var/lib/docker and formatted with xfs file system. Docker storage is configured to use overlay2 filesystem:

```bash
$ ansible -i hosts nodes -m shell -a "cat /etc/sysconfig/docker-storage && docker info"

# docker info
Containers: 4
 Running: 4
 Paused: 0
 Stopped: 0
Images: 4
Server Version: 1.12.6
Storage Driver: overlay2
...
```

### API service status

OpenShift API service runs on all master instances. To see the status of the service, view the master-api pods in the kube-system project:

```bash
$ oc get pod -n kube-system -l openshift.io/component=api
NAME                             READY     STATUS    RESTARTS   AGE
master-api-myserver.com          1/1       Running   0          56d
```

API service exposes a health check, which can be queried externally using the API host name:

```bash
$ oc get pod -n kube-system -o wide
NAME                                               READY     STATUS    RESTARTS   AGE       IP            NODE
master-api-myserver.com                            1/1       Running   0          7h        10.240.0.16   myserver.com/healthz

$ curl -k https://myserver.com/healthz
ok
```

### Controller role verification

OpenShift Container Platform controller service, is available across all master hosts. The service runs in active/passive mode, meaning it should only be running on one master at any time.
  Verify the master host running the controller service as a cluster-admin user:


```bash
$ oc get -n kube-system cm openshift-master-controllers -o yaml
apiVersion: v1
kind: ConfigMap
metadata:
  annotations:
    control-plane.alpha.kubernetes.io/leader: '{"holderIdentity":"master-ose-master-0.example.com-10.19.115.212-dnwrtcl4","leaseDurationSeconds":15,"acquireTime":"2018-02-17T18:16:54Z","renewTime":"2018-02-19T13:50:33Z","leaderTransitions":16}'
  creationTimestamp: 2018-02-02T10:30:04Z
  name: openshift-master-controllers
  namespace: kube-system
  resourceVersion: "17349662"
  selfLink: /api/v1/namespaces/kube-system/configmaps/openshift-master-controllers
  uid: 08636843-0804-11e8-8580-fa163eb934f0
```

The command outputs the current master controller in the control-plane.alpha.kubernetes.io/leader annotation, within the holderIdentity property as:

master-<hostname>-<ip>-<8_random_characters>


Find the hostname of the master host by filtering the output using the following:

```bash
$ oc get -n kube-system cm openshift-master-controllers -o json | jq -r '.metadata.annotations[] | fromjson.holderIdentity | match("^master-(.*)-[0-9.]*-[0-9a-z]{8}$") | .captures[0].string'
```

### Verifying correct Maximum Transmission Unit (MTU) size

Verifying the maximum transmission unit (MTU) prevents a possible networking misconfiguration that can masquerade as an SSL certificate issue.

When a packet is larger than the MTU size that is transmitted over HTTP, the physical network router is able to break the packet into multiple packets to transmit the data.
However, when a packet is larger than the MTU size is that transmitted over HTTPS, the router is forced to drop the packet.

Installation produces certificates that provide secure connections to multiple components that include:

* master hosts
* node hosts
* infrastructure nodes
* registry
* router

These certificates can be found within the /etc/origin/master directory for the master nodes and /etc/origin/node directory for the infra and app nodes.

```bash
$ oc -n default get dc docker-registry -o jsonpath='{.spec.template.spec.containers[].env[?(@.name=="REGISTRY_OPENSHIFT_SERVER_ADDR")].value}{"\n"}'
docker-registry.default.svc:5000

$ curl -kv https://docker-registry.default.svc:5000/healthz
* About to connect() to docker-registry.default.svc port 5000 (#0)
*   Trying 172.30.11.171...
* Connected to docker-registry.default.svc (172.30.11.171) port 5000 (#0)
* Initializing NSS with certpath: sql:/etc/pki/nssdb
*   CAfile: /etc/pki/tls/certs/ca-bundle.crt
  CApath: none
* SSL connection using TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
* Server certificate:
*       subject: CN=172.30.11.171
*       start date: Oct 18 05:30:10 2017 GMT
*       expire date: Oct 18 05:30:11 2019 GMT
*       common name: 172.30.11.171
*       issuer: CN=openshift-signer@1508303629
> GET /healthz HTTP/1.1
> User-Agent: curl/7.29.0
> Host: docker-registry.default.svc:5000
> Accept: */*
>
< HTTP/1.1 200 OK        <----
< Cache-Control: no-cache
< Date: Tue, 24 Oct 2017 19:42:35 GMT
< Content-Length: 0
< Content-Type: text/plain; charset=utf-8
<
* Connection #0 to host docker-registry.default.svc left intact
```

The above example output shows the MTU size being used to ensure the SSL connection is correct. The attempt to connect is successful, followed by connectivity being established and completes with initializing the NSS with the certpath and all the server certificate information regarding the docker-registry.


An improper MTU size results in a timeout:

```bash
$ curl -v https://docker-registry.default.svc:5000/healthz
* About to connect() to docker-registry.default.svc port 5000 (#0)
*   Trying 172.30.11.171...
* Connected to docker-registry.default.svc (172.30.11.171) port 5000 (#0)
* Initializing NSS with certpath: sql:/etc/pki/nssdb
...
...
```

(See https://access.redhat.com/documentation/en-us/openshift_container_platform/3.11/html-single/day_two_operations_guide/#day_two_environment_health_checks to fix the issue)

View the MTU size of the desired Ethernet device (i.e. eth0):

```bash
$ ip link show eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT qlen 1000
    link/ether fa:16:3e:92:6a:86 brd ff:ff:ff:ff:ff:ff
```

To change the MTU size, modify the appropriate node configuration map and set a value that is 50 bytes smaller than output provided by the ip command.

```bash
$ oc get cm -n openshift-node
NAME                       DATA      AGE
node-config-all-in-one     1         1d
node-config-compute        1         1d
node-config-infra          1         1d
node-config-master         1         1d
node-config-master-infra   1         1d

$ oc get cm node-config-compute -o yaml
...
...
networkConfig:
   mtu: 1450
...
...
```

Save the changes and reboot the node


### NTP synchronization

Check if all nodes have NTP activated and sync.

```bash
$ ansible -i hosts -m shell -a 'timedatectl | grep NTP' -u quicklab -b
```


### System Entropy

OpenShift Container Platform uses entropy to generate random numbers for objects such as IDs or SSL traffic. These operations wait until there is enough entropy to complete the task.
Without enough entropy, the kernel is not able to generate these random numbers with sufficient speed, which can lead to timeouts and the refusal of secure connections.


```bash
$ ansible -i hosts -m shell -a 'cat /proc/sys/kernel/random/entropy_avail' -u quicklab -b
```

### OpenShift Version and Packages match

Check the list of OCP installed packages and their version. Check OCP version.

```bash
$ ansible -i hosts --limit nodes  -m shell -a "yum list installed | grep openshift" -u quicklab -b
$ ansible -i hosts --limit nodes  -m shell -a "/usr/bin/openshift version" -u quicklab -b
```

### Router Sharding Status



<br><br>
## Openshift 3 Certificates

### Official Documentation

https://docs.openshift.com/container-platform/3.11/day_two_guide/certificate_management.html
https://docs.openshift.com/container-platform/3.11/install_config/redeploying_certificates.html


We have to differentiate three kinds of certificates in a OCP Deployment:

* Internal Certificates:

Generated by the installer and used to sign internal communications between openshift components, for example the etcd

* Router Certificates:

Certificates exposed in the router pods to sign communications against the exposed routes.

* Master Certificates:

Used to expose API to the customer, it is usually signed by the Corporate CA.


#### Check Certificate Expiration

We can use openshift-ansible to check future expiration of certificates, running following playbook:

```bash
$ cd /usr/share/ansible/openshift-ansible && ansible-playbook -i hosts /usr/share/ansible/openshift-ansible/playbooks/openshift-checks/certificate_expiry/easy-mode.yaml -e openshift_certificate_expiry_html_report_path=/tmp/cert-expiry-report.html -e openshift_certificate_expiry_json_results_path=/tmp/cert-expiry-report.json -e openshift_is_atomic=false -e ansible_distribution=RedHat
```

This playbook will generate a html report and a json file with information about expiration.


#### Redeploying Master Certificates Only

```bash
$ cd /usr/share/ansible/openshift-ansible && ansible-playbook -i hosts /usr/share/ansible/openshift-ansible/playbooks/openshift-master/redeploy-certificates.yml
```


#### Redeploying etcd Certificates Only

```bash
$ cd /usr/share/ansible/openshift-ansible && ansible-playbook -i hosts /usr/share/ansible/openshift-ansible/playbooks/openshift-etcd/redeploy-certificates.yml
```

#### Redeploying Node Certificates 

OpenShift Container Platform automatically rotates node certificates when they get close to expiring


#### Router Custom Certificate Renew

For this case manual redeploy is prefered.


```bash
$ cat router-custom.crt ca.crt router-custom.key > router-custom.pem
$ oc login -u admin
$ oc project default
$ oc export secret router-custom-certs > ~/old-router-custom-certs-secret.yaml
$ oc create secret tls router-custom-certs --cert=router-custom.pem --key=router-custom.key -o json --dry-run | oc replace -f -
$ oc annotate service router-custom service.alpha.openshift.io/serving-cert-secret-name- service.alpha.openshift.io/serving-cert-signed-by-
$ oc annotate service router-custom service.alpha.openshift.io/serving-cert-secret-name=router-custom-certs
$ oc rollout latest dc/router-custom

```


#### Certificate HealthCheck

The following procedure can be executed in order to verify redeploy certificate healthcheck.


Openshift Cluster certificates health.

* etcd certificates.

```bash
$ oc get pods --all-namespaces
$ oc get nodes

master# source /etc/etcd/etcd.conf
master# etcdctl --cert-file=$ETCD_PEER_CERT_FILE --key-file=$ETCD_PEER_KEY_FILE \
  --ca-file=/etc/etcd/ca.crt --endpoints=$ETCD_LISTEN_CLIENT_URLS cluster-health
master# etcdctl --cert-file=$ETCD_PEER_CERT_FILE --key-file=$ETCD_PEER_KEY_FILE \
  --ca-file=/etc/etcd/ca.crt --endpoints=$ETCD_LISTEN_CLIENT_URLS member list
```

* Router and Registry certificates health.

```bash
$ oc -n default get deploymentconfigs/router-custom
$ oc -n default get deploymentconfigs/docker-registry
$ oc -n default get deploymentconfigs/registry-console
$ curl -kv https://docker-registry-default.apps.info.net/healthz
$ firefox https://registry-console-default.apps.info.net
```

* External Registry Access.

```bash
$ oc whoami -t
$ sudo docker login -p TOKEN -e unused -u unused https://docker-registry-default.apps.info.net
$ sudo docker pull https://docker-registry-default.apps.info.net/httpd-test/ruby-22-centos7:latest
$ sudo docker images
$ sudo docker tag e42d0dccf073 https://docker-registry-default.apps.info.net/httpd-test/ruby-22-centos7:test
$ sudo docker push https://docker-registry-default.apps.info.net/httpd-test/ruby-22-centos7:test
```

* Check certificate renew.

```bash
$ cd /usr/share/ansible/openshift-ansible && ansible-playbook -i hosts /usr/share/ansible/openshift-ansible/playbooks/certificate_expiry/easy-mode.yaml -e openshift_certificate_expiry_html_report_path=/tmp/cert-expiry-report.html -e openshift_certificate_expiry_json_results_path=/tmp/cert-expiry-report.json -e openshift_is_atomic=false -e ansible_distribution=RedHat
```

<br><br>
## Scaling and Performance

### Official Documentation

https://docs.openshift.com/container-platform/3.11/scaling_performance/index.html


### Add new nodes 

You can add new hosts to your cluster by running the scaleup.yml playbook. This playbook queries the master, generates and distributes new certificates for the new hosts, and then runs the configuration playbooks on only the new hosts. Before running the scaleup.yml playbook, complete all prerequisite host preparation steps.

https://docs.openshift.com/container-platform/3.11/install/host_preparation.html#preparing-for-advanced-installations-origin

* Ensure you have the latest playbooks by updating the openshift-ansible package:

```bash
$ yum update openshift-ansible
```

* Edit your inventory file (hosts in this case)  and add new_<host_type> to the [OSEv3:children] section:

```bash
[OSEv3:children]
masters
nodes
new_nodes
```
To add new master hosts, add new_masters


* Create a [new_<host_type>] section to specify host information for the new hosts. Format this section like an existing section, as shown in the following example of adding a new node:

```bash
...
[new_nodes]
node3.example.com openshift_node_group_name='node-config-infra'
...
```
When adding new masters, add hosts to both the [new_masters] section and the [new_nodes] section to ensure that the new master host is part of the OpenShift SDN.

* Change to the playbook directory and run the scaleup.yml playbook

For additional nodes:

```bash
$ cd /usr/share/ansible/openshift-ansible
$ ansible-playbook -i /path/to/hosts playbooks/openshift-node/scaleup.yml
```

For additional masters:

```bash
$ cd /usr/share/ansible/openshift-ansible
$ ansible-playbook -i /path/to/hosts playbooks/openshift-master/scaleup.yml
```

* Set the node label to logging-infra-fluentd=true, if you deployed the EFK stack in your cluster.

```bash
$ oc label node/new-node.example.com logging-infra-fluentd=true
```

* Verify the installation

Verify that the master is started and nodes are registered and reporting in Ready status.

```bash
$ oc get nodes
NAME                   STATUS    ROLES     AGE       VERSION
master.example.com     Ready     master    7h        v1.9.1+a0ce1bc657
node1.example.com      Ready     compute   7h        v1.9.1+a0ce1bc657
node2.example.com      Ready     compute   7h        v1.9.1+a0ce1bc657
```

To verify that the web console is installed correctly, use the master host name and the web console port number to access the web console with a web browser.

```bash
$ firefox https://master.openshift.com:443/console
```

### Overcommitting

You can use overcommit procedures so that resources such as CPU and memory are more accessible to the parts of your cluster that need them.

Note that when you overcommit, there is a risk that another application may not have access to the resources it requires when it needs them, which will result in reduced performance. However, this may be an acceptable trade-off in favor of increased density and reduced costs. For example, development, quality assurance (QA), or test environments may be overcommitted, whereas production might not be.


```bash
$ cat hosts
...
openshift_master_admission_plugin_config={"ClusterResourceOverride": {"configuration": {"apiVersion": "v1", "cpuRequestToLimitPercent": 20, "kind": "ClusterResourceOverrideConfig"}}, "PersistentVolumeClaimResize": {"configuration": {"apiVersion": "v1", "disable": false, "kind": "DefaultAdmissionConfig"}}}
...
```

* cpuRequestToLimitPercent

(optional, 1-100) If a container CPU limit has been specified or defaulted, the CPU request is overridden to this percentage of the limit.


* memoryRequestToLimitPercent

(optional, 1-100) If a container memory limit has been specified or defaulted, the memory request is overridden to this percentage of the limit.


### Optimizing Network Performance

The OpenShift SDN uses OpenvSwitch, virtual extensible LAN (VXLAN) tunnels, OpenFlow rules, and iptables. This network can be tuned by using jumbo frames, network interface cards (NIC) offloads, multi-queue, and ethtool settings.

#### Optimizing the MTU for Your Network

There are two important maximum transmission units (MTUs): the network interface card (NIC) MTU and the SDN overlay’s MTU.

The NIC MTU must be less than or equal to the maximum supported value of the NIC of your network. If you are optimizing for throughput, pick the largest possible value. If you are optimizing for lowest latency, pick a lower value.

The SDN overlay’s MTU must be less than the NIC MTU by 50 bytes at a minimum. This accounts for the SDN overlay header. So, on a normal ethernet network, set this to 1450. On a jumbo frame ethernet network, set this to 8950.

This 50 byte overlay header is relevant to the OpenShift SDN. Other SDN solutions might require the value to be more or less.


```bash
$ oc get cm node-config-compute -o yaml
...
...
networkConfig:
   mtu: 1450
...
...
```


### Routing Optimization

The OpenShift Container Platform router is the ingress point for all external traffic destined for OpenShift Container Platform services.

When evaluating a single HAProxy router performance in terms of HTTP requests handled per second, the performance varies depending on many factors. In particular:

* HTTP keep-alive/close mode,

* route type

* TLS session resumption client support

* number of concurrent connections per target route

* number of target routes

* backend server page size

* underlying infrastructure (network/SDN solution, CPU, and so on)


While performance in your specific environment will vary, our lab tests on a public cloud instance of size 4 vCPU/16GB RAM, a single HAProxy router handling 100 routes terminated by backends serving 1kB static pages is able to handle the following number of transactions per second.

More info:

https://docs.openshift.com/container-platform/3.11/scaling_performance/routing_optimization.html


### Managing Huge Pages

Memory is managed in blocks known as pages. On most systems, a page is 4Ki. 1Mi of memory is equal to 256 pages; 1Gi of memory is 262,144 pages, and so on. CPUs have a built-in memory management unit that manages a list of these pages in hardware. The Translation Lookaside Buffer (TLB) is a small hardware cache of virtual-to-physical page mappings. If the virtual address passed in a hardware instruction can be found in the TLB, the mapping can be determined quickly. If not, a TLB miss occurs, and the system falls back to slower, software-based address translation, resulting in performance issues. Since the size of the TLB is fixed, the only way to reduce the chance of a TLB miss is to increase the page size.

A huge page is a memory page that is larger than 4Ki. On x86_64 architectures, there are two common huge page sizes: 2Mi and 1Gi. Sizes vary on other architectures. In order to use huge pages, code must be written so that applications are aware of them. Transparent Huge Pages (THP) attempt to automate the management of huge pages without application knowledge, but they have limitations.


More info:

https://docs.openshift.com/container-platform/3.11/scaling_performance/managing_hugepages.html

<br><br>
## Openshift 3 Storage

### Official Documentation

https://docs.openshift.com/container-platform/3.11/install_config/storage_examples/gluster_example.html
https://access.redhat.com/documentation/en-us/red_hat_gluster_storage/3.5/html-single/administration_guide/index


### Troubleshooting OCS3 independent mode

Here are a series of useful commands to verify the status of OCS and Heketi. Remember that independent OCS is mounted on an external cluster, so we must connect to these machines to know their status. On the other hand, Heketi is a pod within the glusterfs project that manages the independent OCS nodes from a central point. Heketi exposes an API that is the one that Openshift uses to create, delete and manage dynamic volumes provided by OCS.


* Glusterd service status

```bash
[root@srv04 ~]$ systemctl status glusterd
...
```

* Status of volumes managed by Gluster. We see that everyone is online.

```bash
[root@srv04 ~]$ gluster vol status
Status of volume: heketidbstorage
Gluster process                             TCP Port  RDMA Port  Online  Pid
------------------------------------------------------------------------------
Brick 10.66.8.62:/var/lib/heketi/mounts/vg_
7f6984d6ee744833bc85ba7cf3c4d77f/brick_1e34
fa7cd209930837302f5079d0a9f4/brick          49152     0          Y       3036
Brick 10.66.8.66:/var/lib/heketi/mounts/vg_
aeb5254e5ee3b863b841fb42fe24e531/brick_5d2f
56e58467fdf5210582b31876caeb/brick          49152     0          Y       3762
Brick 10.66.8.65:/var/lib/heketi/mounts/vg_
086f3a9967ce9463d68e8e0413d24109/brick_5d75
c89e2ebd66e82a8aa08d0d16cd77/brick          49152     0          Y       21963
Self-heal Daemon on localhost               N/A       N/A        Y       24735
...
```

* List of all volumes created in OCS.

```bash
[root@srv04 ~]$ gluster vol list
...
```

* Detailed information of a specific volume.

```bash
[root@srv04 ~]$ gluster vol info vol-app-ind_arquitectura_gfs-data-pro-ind_579b091c-a195-11e9-8c91-566f3ad8000a
...
```

* Information about the health status of a volume.
  If there are still nodes that have not been able to replicate the current status, so they have pending changes. Number entries equal to 0, means that there are no pending changes to write to the node's brick. 

```bash
[root@srv04 ~]$ gluster volume heal vol-app-ind_arquitectura_gfs-data-pro-ind_579b091c-a195-11e9-8c91-566f3ad8000a info
...
```

* Heketi pod commands.

```bash
$ oc project glusterfs
$ oc get pods
$ oc rsh heketi-storage-ind-1-z97hw

$$ heketi-cli volume list
$$ heketi-cli blockvolume list
$$ heketi-cli topology info
...
```


<br><br>
## Openshift 3 Backup

### Official Documentation

https://docs.openshift.com/container-platform/3.11/day_two_guide/environment_backup.html


### Master backup

It is recomended to execute the backup procedure before any significant Openshift cluster infrastructure change as an upgrade.

* On each master node make a backup of the critical files:

```bash
master$ MYBACKUPDIR=/backup/$(hostname)/$(date +%Y%m%d)
master$ sudo mkdir -p ${MYBACKUPDIR}/etc/sysconfig
master$ sudo cp -aR /etc/origin ${MYBACKUPDIR}/etc
master$ sudo cp -aR /etc/sysconfig/ ${MYBACKUPDIR}/etc/sysconfig/
```

```bash
master$ MYBACKUPDIR=/backup/$(hostname)/$(date +%Y%m%d)
master$ sudo mkdir -p ${MYBACKUPDIR}/etc/sysconfig
master$ sudo mkdir -p ${MYBACKUPDIR}/etc/pki/ca-trust/source/anchors
master$ sudo cp -aR /etc/sysconfig/{iptables,docker-*,flanneld} ${MYBACKUPDIR}/etc/sysconfig/
master$ sudo cp -aR /etc/dnsmasq* /etc/cni ${MYBACKUPDIR}/etc/
master$ sudo cp -aR /etc/pki/ca-trust/source/anchors/* ${MYBACKUPDIR}/etc/pki/ca-trust/source/anchors/
```

```bash
master$ MYBACKUPDIR=/backup/$(hostname)/$(date +%Y%m%d)
master$ sudo mkdir -p ${MYBACKUPDIR}
master$ rpm -qa | sort | sudo tee $MYBACKUPDIR/packages.txt
```

* If needed backup can be compressed:

```bash
master$ MYBACKUPDIR=/backup/$(hostname)/$(date +%Y%m%d)
master$ sudo tar -zcvf /backup/$(hostname)-$(date +%Y%m%d).tar.gz $MYBACKUPDIR
master$ sudo rm -Rf ${MYBACKUPDIR}
```

### Node backup

Creating a backup of a node host is a different use case from backing up a master host. Because master hosts contain many important files, creating a backup is highly recommended. However, the nature of nodes is that anything special is replicated over the nodes in case of failover, and they typically do not contain data that is necessary to run an environment. If a backup of a node contains something necessary to run an environment, then a creating a backup is recommended.

On each node run the following procedure:

* Node config files backup

```bash
node$ MYBACKUPDIR=/backup/$(hostname)/$(date +%Y%m%d)
node$ sudo mkdir -p ${MYBACKUPDIR}/etc/sysconfig
node$ sudo cp -aR /etc/origin ${MYBACKUPDIR}/etc
node$ sudo cp -aR /etc/sysconfig/atomic-openshift-node ${MYBACKUPDIR}/etc/sysconfig/
```

```bash
node$ MYBACKUPDIR=/backup/$(hostname)/$(date +%Y%m%d)
node$ sudo mkdir -p ${MYBACKUPDIR}/etc/sysconfig
node$ sudo mkdir -p ${MYBACKUPDIR}/etc/pki/ca-trust/source/anchors
node$ sudo cp -aR /etc/sysconfig/{iptables,docker-*,flanneld} ${MYBACKUPDIR}/etc/sysconfig/
node$ sudo cp -aR /etc/dnsmasq* /etc/cni ${MYBACKUPDIR}/etc/
node$ sudo cp -aR /etc/pki/ca-trust/source/anchors/* ${MYBACKUPDIR}/etc/pki/ca-trust/source/anchors/
```

```bash
node$ MYBACKUPDIR=/backup/$(hostname)/$(date +%Y%m%d)
node$ sudo mkdir -p ${MYBACKUPDIR}
node$ rpm -qa | sort | sudo tee $MYBACKUPDIR/packages.txt
```

* If needed backup can be compressed:

```bash
node$ MYBACKUPDIR=/backup/$(hostname)/$(date +%Y%m%d)
node$ sudo tar -zcvf /backup/$(hostname)-$(date +%Y%m%d).tar.gz $MYBACKUPDIR
node$ sudo rm -Rf ${MYBACKUPDIR}
```

### Ansible inventory and instalaton files backup

It is recommended to keep a backup of ansible inventory and installation files used on the bastion host when installing the cluster. These files will be needed during the whole openshift livecycle.
Use git in order to track changes in these files.


### Application data backup

In many cases, you can back up application data by using the oc rsync command, assuming rsync is installed within the container image. The Red Hat rhel7 base image contains rsync. Therefore, all images that are based on rhel7 contain it as well.

This is a generic backup of application data and does not take into account application-specific backup procedures, for example, special export and import procedures for database systems.

* Get the application data mountPath from the deploymentconfig:

```bash
$ oc get dc/jenkins -o jsonpath='{ .spec.template.spec.containers[?(@.name=="jenkins")].volumeMounts[?(@.name=="jenkins-data")].mountPath }'
/var/lib/jenkins
```

* Get the name of the pod that is currently running:

```bash
$ oc get pod --selector=deploymentconfig=jenkins -o jsonpath='{ .metadata.name }'
jenkins-1-37nux
```

* Use the oc rsync command to copy application data:

```bash
$ oc rsync jenkins-1-37nux:/var/lib/jenkins /tmp/
```

### etcd backup

etcd is the key value store for all object definitions, as well as the persistent master state. Other components watch for changes, then bring themselves into the desired state.

```bash
$ etcdctl -v
etcdctl version: 3.2.22
API version: 2
```

The etcd backup process is composed of two different procedures:

* Configuration backup: Including the required etcd configuration and certificates

* Data backup: Including both v2 and v3 data model.

You can perform the data backup process on any host that has connectivity to the etcd cluster, where the proper certificates are provided, and where the etcdctl tool is installed.
The backup files must be copied to an external system, ideally outside the OpenShift Container Platform environment, and then encrypted.


#### Backing up etcd configuration files

On each master node where etcd cluster is running, execute the following procedure:

```bash
master$ mkdir -p /backup/etcd-config-$(date +%Y%m%d)/
master$ cp -R /etc/etcd/ /backup/etcd-config-$(date +%Y%m%d)/
```

#### Backing up etcd data

Before backing up etcd:

* etcdctl binaries must be available or, in containerized installations, the rhel7/etcd container must be available.

* Ensure that the OpenShift Container Platform API service is running.

* Ensure connectivity with the etcd cluster (port 2379/tcp).

* Ensure the proper certificates to connect to the etcd cluster.


```bash
master$ source /etc/etcd/etcd.conf
master$ etcdctl --cert-file=$ETCD_PEER_CERT_FILE --key-file=$ETCD_PEER_KEY_FILE \
  --ca-file=/etc/etcd/ca.crt --endpoints=$ETCD_LISTEN_CLIENT_URLS cluster-health
master$ etcdctl --cert-file=$ETCD_PEER_CERT_FILE --key-file=$ETCD_PEER_KEY_FILE \
  --ca-file=/etc/etcd/ca.crt --endpoints=$ETCD_LISTEN_CLIENT_URLS member list
```

If etcd runs as a static pod, run the following commands:

* Check if etcd runs as a static pod.

```bash
$ oc get pods -n kube-system | grep etcd
srv01.info.net          1/1       Running   0          126d
srv02.info.net          1/1       Running   4          33d
srv03.info.net          1/1       Running   2          126d
```

* Obtain the etcd endpoint IP address from the static pod manifest:

```bash
$ export ETCD_POD_MANIFEST="/etc/origin/node/pods/etcd.yaml"
$ export ETCD_EP=$(grep https ${ETCD_POD_MANIFEST} | cut -d '/' -f3)
```

* Get etcd pod name:

```bash
$ oc login -u system:admin
$ export ETCD_POD=$(oc get pods -n kube-system | grep -o -m 1 '\S*etcd\S*')
```

* Take a snapshot of the etcd data in the pod and store it locally:

```bash
$ oc project kube-system
$ oc exec ${ETCD_POD} -c etcd -- /bin/bash -c "ETCDCTL_API=3 etcdctl \
    --cert /etc/etcd/peer.crt \
    --key /etc/etcd/peer.key \
    --cacert /etc/etcd/ca.crt \
    --endpoints $ETCD_EP \
    snapshot save /var/lib/etcd/snapshot.db"
```

If it is saved in the /var/lib/etcd folder, it is the same as saving it on the master machine where it runs, since it has that host folder mounted where the pod is running


### Project backup

Creating a backup of all relevant data involves exporting all important information, then restoring into a new project if needed.

* List all the relevant data to back up in the target project (myproject in this case):

```bash
$ oc project myproject
$ oc get all
NAME         TYPE      FROM      LATEST
bc/ruby-ex   Source    Git       1

NAME               TYPE      FROM          STATUS     STARTED         DURATION
builds/ruby-ex-1   Source    Git@c457001   Complete   2 minutes ago   35s

NAME                 DOCKER REPO                                     TAGS      UPDATED
is/guestbook         10.111.255.221:5000/myproject/guestbook         latest    2 minutes ago
is/hello-openshift   10.111.255.221:5000/myproject/hello-openshift   latest    2 minutes ago
is/ruby-22-centos7   10.111.255.221:5000/myproject/ruby-22-centos7   latest    2 minutes ago
is/ruby-ex           10.111.255.221:5000/myproject/ruby-ex           latest    2 minutes ago

NAME                 REVISION   DESIRED   CURRENT   TRIGGERED BY
dc/guestbook         1          1         1         config,image(guestbook:latest)
dc/hello-openshift   1          1         1         config,image(hello-openshift:latest)
dc/ruby-ex           1          1         1         config,image(ruby-ex:latest)

NAME                   DESIRED   CURRENT   READY     AGE
rc/guestbook-1         1         1         1         2m
rc/hello-openshift-1   1         1         1         2m
rc/ruby-ex-1           1         1         1         2m

NAME                  CLUSTER-IP       EXTERNAL-IP   PORT(S)             AGE
svc/guestbook         10.111.105.84    <none>        3000/TCP            2m
svc/hello-openshift   10.111.230.24    <none>        8080/TCP,8888/TCP   2m
svc/ruby-ex           10.111.232.117   <none>        8080/TCP            2m

NAME                         READY     STATUS      RESTARTS   AGE
po/guestbook-1-c010g         1/1       Running     0          2m
po/hello-openshift-1-4zw2q   1/1       Running     0          2m
po/ruby-ex-1-build           0/1       Completed   0          2m
po/ruby-ex-1-rxc74           1/1       Running     0          2m
```


* Export the project objects to a .yaml files.

```bash
$ oc get -o yaml --export all > project.yaml
```

* Export the project’s role bindings, secrets, service accounts, and persistent volume claims:

```bash
$ for object in rolebindings serviceaccounts secrets imagestreamtags cm egressnetworkpolicies rolebindingrestrictions limitranges resourcequotas pvc templates cronjobs statefulsets hpa deployments replicasets poddisruptionbudget endpoints
do
  oc get -o yaml --export $object > $object.yaml
done
```

* To list all the namespaced objects:

```bash
$ oc api-resources --namespaced=true -o name
```

## Openshift 3 Users and Roles 

### Official Documentation

https://docs.openshift.com/container-platform/3.11/admin_guide/manage_users.html


### Openshift Users and Groups

#### Creating a User

OpenShift defaults create new users automatically when they first log in. If the user credentials are accepted by the identity provider (LDAP for example), OpenShift creates the user object (if allowed by OCP create policy).


```bash
$ oc create user test-user
$ oc policy add-role-to-user edit test-user
$ oc policy remove-role-from-user edit test-user
```


#### Viewing User and Identity Lists

OpenShift Container Platform internally stores details like role-based access control (RBAC) information and group membership. Two object types contain user data outside the identification provider: user and identity.


```bash
$ oc get user
NAME      UID                                    FULL NAME   IDENTITIES
demo     75e4b80c-dbf1-11e5-8dc6-0e81e52cc949               htpasswd_auth:demo
```

```bash
$ oc get identity
NAME                  IDP NAME        IDP USER NAME   USER NAME   USER UID
htpasswd_auth:demo    htpasswd_auth   demo            demo        75e4b80c-dbf1-11e5-8dc6-0e81e52cc949
```


#### Creating Groups

Users can be organized into one or more groups made up from a set of users. Groups are useful for managing many users at one time, such as for authorization policies, or to grant permissions to multiple users at once.

If your organization is using LDAP, you can synchronize any LDAP records to OpenShift Container Platform so that you can configure groups on one place. This presumes that information about your users is in an LDAP server.

https://docs.openshift.com/container-platform/3.11/install_config/syncing_groups_with_ldap.html#install-config-syncing-groups-with-ldap

* To create a new group and asign john and betty to it:

```bash
$ oc adm groups new west john betty
```

```bash
$ oc get groups
NAME      USERS
west      john, betty
```


### Cluster Administration

Cluster administrators can create projects and delegate administrative rights for the project to any user. In OpenShift Container Platform, projects are used to group and isolate related objects.
Administrators can apply roles to users and groups that allow or restrict their ability to create projects. Roles can be assigned prior to a user's initial login.

* Restricting project creation

```bash
$ oc adm policy remove-cluster-role-from-group self-provisioner system:authenticated system:authenticated:oauth
```

* Granting project creation

```bash
$ oc adm policy add-cluster-role-to-group self-provisioner system:authenticated system:authenticated:oauth
```

### Creating a Project

For users granted with project creation permission they can create a project named testme:

```bash
$ oc new-project testme --description="testme description" --display-name="testme"
```


### Role Bindings

Adding (binding) a role to users or groups gives the user or group the  access granted by the role.


* Cluster admin role

```bash
master$ oc adm policy add-cluster-role-to-user cluster-admin admin
```

* Granting developer user read-only access to information about the cluster

```bash
$ oc adm policy add-cluster-role-to-user cluster-status developer
```

* Restricting project creation

```bash
$ oc adm policy remove-cluster-role-from-group self-provisioner system:authenticated system:authenticated:oauth
```

* Granting project creation

```bash
$ oc adm policy add-cluster-role-to-group self-provisioner system:authenticated system:authenticated:oauth
```

* Granting admin role on project testme

```bash
$ oc adm policy add-role-to-user admin developer -n testme
```

* Granting developer role on project testme

```bash
$ oc adm policy add-role-to-user edit developer -n testme
```

* Granting developer user read-only access to project testme

```bash
$ oc adm policy add-role-to-user basic-user developer -n testme
```


#### Reading Cluster Policies

```bash
$ oc describe clusterPolicyBindings :default
```

#### Reading Local Policies

```bash
$ oc describe policyBindings :default
```


### Security Context Constraints (SCCs)

OpenShift provides security context constraints (SCCs) which control the actions a pod can perform and what resources can access.


* List SCCs

```bash
$ oc get scc
```


* Get SCC description

```bash
$ oc describe scc sccname
```

* Grant SCC to user/group 

```bash
$ oc adm policy add-scc-to-user sccname username
$ oc adm policy add-scc-to-group sccname groupname
```

* Remove SCC to user/group

```bash
$ oc adm policy remove-scc-from-user sccname username
$ oc adm policy remove-scc-from-group sccname groupname
```

### Service Account

Service accounts provide a way to control API access without sharing a user’s credentials. For an application that requires a capability not granted by the restricted SCC an specific service account and added it to the appropriate SCC.


Deploying an app that requires elevated privileges by default is not supported by OpenShift. If this use case is really needed  a service account can be created, added to deployment configuration, and then add the service account to an SCC, such as anyuid, which meets the requirements to run as root user in the container.


* Create a new service account named rootuser.

```bash
$ oc create serviceaccount rootuser
```

* Modify the deployment configuration for the application.

```bash
$ oc patch dc/testme --patch '{"spec":{"template":{"spec":{"serviceAccountName": "rootuser"}}}}'
```

* Add rootuser service account to the anyuid SCC to run as the root user in the container.

```bash
$ oc adm policy add-scc-to-user anyuid -z rootuser
```


### Demo

...



<br><br>
## Openshift 3 Logging with ELK

### Official Documentation

https://docs.openshift.com/container-platform/3.11/install_config/aggregate_logging.html


<br><br>
## Openshift 3 Monitoring with Prometheus and Grafana

### Official Documentation

https://docs.openshift.com/container-platform/3.11/install_config/prometheus_cluster_monitoring.html


