# openshift-workshop

## Project Title

Day 2 Operations for Openshift 3

## Disclaimer

**This is a reference manual for day 2 operations on Openshift 3 for didactic use only so it is not expected to use it for production environments.** 
**Please use the official documentation instead for production usage:**

https://docs.openshift.com/container-platform/3.11/welcome/index.html   


## Openshift 3 Architecture

The following workshop applies for a test Openshift 3.11 cluster using OCS 3.11 with gluster in independent mode.

![alt text]( images/arch-independent.png "Architecture")  


## Openshift 3 Upgrade

### Official Documentation

https://docs.openshift.com/container-platform/3.11/upgrading/index.html#install-config-upgrading-strategy-inplace

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

* From bastion node, upgrade the control plane

```bash
$ cd /usr/share/ansible/openshift-ansible && ansible-playbook -i hosts playbooks/byo/openshift-cluster/upgrades/v3_11/upgrade_control_plane.yml
```

* From bastion node, upgrade infra nodes

```bash
$ cd /usr/share/ansible/openshift-ansible && ansible-playbook -i hosts playbooks/byo/openshift-cluster/upgrades/v3_11/upgrade_nodes.yml -e openshift_upgrade_nodes_label="node-role.kubernetes.io/infra=true"
```

* From bastion node, upgrade worker nodes

```bash
$ cd /usr/share/ansible/openshift-ansible && ansible-playbook -i hosts playbooks/byo/openshift-cluster/upgrades/v3_11/upgrade_nodes.yml -e openshift_upgrade_nodes_label="node-role.kubernetes.io/compute=true"
```


* Quick upgrade verify

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

* Run Openshift 3 HealthCheck procedure (next section)



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
# oc get nodes
...
```
(Ready status means that master hosts can communicate with node hosts and that the nodes are ready to run pods (excluding the nodes in which scheduling is disabled))


#### SkyDNS

SkyDNS provides name resolution of local services running in OpenShift Container Platform. This service uses TCP and UDP port 8053.

```bash
# dig +short docker-registry.default.svc.cluster.local
172.30.150.7

# oc get svc/docker-registry -n default
NAME              CLUSTER-IP     EXTERNAL-IP   PORT(S)    AGE
docker-registry   172.30.150.7   <none>        5000/TCP   3d
```

*172.30.150.7 equivalent IP match*


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
*The HTTP/1.1 200 OK response means the node is correctly connecting.*

```bash
$ oc delete project sdn-test
project "sdn-test" deleted
```

To verify the functionality of the routers, check the registry service once more, but this time from outside the cluster:
(Check external access to SDN )

```bash
$ curl -kv https://docker-registry-default.apps.example.com/healthz
*   Trying 35.xx.xx.92...
* TCP_NODELAY set
* Connected to docker-registry-default.apps.example.com (35.xx.xx.92) port 443 (#0)
...
< HTTP/2 200
```

### DNS

Verify wilcard DNS points to LB

```bash
$ dig *.apps.2e5b.example.opentlc.com
```

Verify all nodes have direct and inverse resolution

```bash
$ ansible -i hosts all -m shell -a 'host $(hostname); host $(ip a | grep "inet 10." | awk  "{print \$2}" | cut -d/ -f1)' -u quicklab -b
```


### Storage

### Nodes free space

Master instances need at least 40 GB of hard disk space for the /var directory. Check the disk usage of a master host using the df command:

```bash
ansible -i hosts -m shell -a "df -hT"
```

### Check Heketi OCS status

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


### Checking PVC and PV

Check all PVC are bond to a PV

```bash
$ oc get pv
$ oc get pvc --all-namespaces
```


### Check PVC and use it on APP

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

The Docker storage disk is mounted as /var/lib/docker and formatted with xfs file system. Docker storage is configured to use overlay2 filesystem:

```bash
$ ansible -i /path/inventory/ocp_inventory_nfs_logging_metrics_311 nodes -m shell -a "cat /etc/sysconfig/docker-storage && docker info"

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

The OpenShift API service runs on all master instances. To see the status of the service, view the master-api pods in the kube-system project:

```bash
$ oc get pod -n kube-system -l openshift.io/component=api
NAME                             READY     STATUS    RESTARTS   AGE
master-api-myserver.com          1/1       Running   0          56d
```

The API service exposes a health check, which can be queried externally using the API host name:

```bash
$ oc get pod -n kube-system -o wide
NAME                                               READY     STATUS    RESTARTS   AGE       IP            NODE
master-api-myserver.com                            1/1       Running   0          7h        10.240.0.16   myserver.com/healthz

$ curl -k https://myserver.com/healthz
ok
```

### Controller role verification

The OpenShift Container Platform controller service, is available across all master hosts. The service runs in active/passive mode, meaning it should only be running on one master at any time.
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
# oc -n default get dc docker-registry -o jsonpath='{.spec.template.spec.containers[].env[?(@.name=="REGISTRY_OPENSHIFT_SERVER_ADDR")].value}{"\n"}'
docker-registry.default.svc:5000

# curl -kv https://docker-registry.default.svc:5000/healthz
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

Check if all nodes have NTP activated and sync

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


* Openshift Cluster certificates health,

```bash
$ oc get pods --all-namespaces
$ oc get nodes

master# source /etc/etcd/etcd.conf
master# etcdctl --cert-file=$ETCD_PEER_CERT_FILE --key-file=$ETCD_PEER_KEY_FILE \
  --ca-file=/etc/etcd/ca.crt --endpoints=$ETCD_LISTEN_CLIENT_URLS cluster-health
master# etcdctl --cert-file=$ETCD_PEER_CERT_FILE --key-file=$ETCD_PEER_KEY_FILE \
  --ca-file=/etc/etcd/ca.crt --endpoints=$ETCD_LISTEN_CLIENT_URLS member list
```

* Router and Registry certificates health,

```bash
$ oc -n default get deploymentconfigs/router-custom
$ oc -n default get deploymentconfigs/docker-registry
$ oc -n default get deploymentconfigs/registry-console
$ curl -kv https://docker-registry-default.apps.info.net/healthz
$ firefox https://registry-console-default.apps.info.net
```

* External Registry Access

```bash
$ oc whoami -t
$ sudo docker login -p TOKEN -e unused -u unused https://docker-registry-default.apps.info.net
$ sudo docker pull https://docker-registry-default.apps.info.net/httpd-test/ruby-22-centos7:latest
$ sudo docker images
$ sudo docker tag e42d0dccf073 https://docker-registry-default.apps.info.net/httpd-test/ruby-22-centos7:test
$ sudo docker push https://docker-registry-default.apps.info.net/httpd-test/ruby-22-centos7:test
```

* Check certificate renew

```bash
$ cd /usr/share/ansible/openshift-ansible && ansible-playbook -i hosts /usr/share/ansible/openshift-ansible/playbooks/certificate_expiry/easy-mode.yaml -e openshift_certificate_expiry_html_report_path=/tmp/cert-expiry-report.html -e openshift_certificate_expiry_json_results_path=/tmp/cert-expiry-report.json -e openshift_is_atomic=false -e ansible_distribution=RedHat
```


## Openshift 3 Users and Roles 

### Official Documentation

https://docs.openshift.com/container-platform/3.11/admin_guide/manage_users.html


## Openshift 3 Logging with ELK

### Official Documentation

https://docs.openshift.com/container-platform/3.11/install_config/aggregate_logging.html


## Openshift 3 Monitoring with Prometheus and Grafana

### Official Documentation

https://docs.openshift.com/container-platform/3.11/install_config/prometheus_cluster_monitoring.html


## Openshift 3 Storage

### Official Documentation

https://docs.openshift.com/container-platform/3.11/install_config/storage_examples/gluster_example.html
https://access.redhat.com/documentation/en-us/red_hat_gluster_storage/3.5/html-single/administration_guide/index


## Openshift 3 Administration

### Official Documentation

https://docs.openshift.com/container-platform/3.11/admin_guide/index.html



## Scaling and Performance

### Official Documentation

https://docs.openshift.com/container-platform/3.11/scaling_performance/index.html


## Openshift 3 Backup

### Official Documentation

https://docs.openshift.com/container-platform/3.11/day_two_guide/environment_backup.html

