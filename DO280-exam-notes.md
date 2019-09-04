# Red Hat OpenShift Admin I (v3.9) DO280/EX280

## 1. Installation - Ansible inventory file & vars

```ini
[workstations]
[nfs]
[masters]
[etcd]
[nodes]
  openshift_node_labels                           # e.g. "{'region':'infra', 'node-role.kubernetes.io/compute':'true'}"
[OSEv3:children]
[nodes:vars]
  # pre-installation vars
  registry_local                                  # registry.lab.example.com
  use_overlay_driver                              # true
  insecure_registry                               # false
  run_docker_offline                              # true
  docker_storage_device                           # /dev/vdb
[OSEv3:vars]
  # general vars
  openshift_deployment_type                       # openshift-enterprise
  openshift_release                               # v3.9
  openshift_image_tag                             # v3.9.14
  openshift_disable_check                         # disk_availability,docker_storage,memory_availability
  # networking
  os_firewall_use_firewalld                       # true
  openshift_master_api_port                       # 443
  openshift_master_console_port                   # 443
  openshift_master_default_subdomain              # apps.lab.example.com
  # authentication
  openshift_master_identity_providers             # [{'name':'htpasswd_auth', 'login':'true', 'challenge':'true',
    'kind':'HTPasswdPasswordIdentityProvider','filename':'/etc/origin/master/htpasswd'}]
  openshift_master_htpasswd_users                 # {'user':'<<HASH>>'}
                                                  # openssl passwd -apr1 <PASSWORD> or htpasswd -nbm <USER> <PASSWORD>
  # nfs
  openshift_enable_unsupported_configurations     # true
  openshift_hosted_registry_storage_kind          # nfs
  openshift_hosted_registry_storage_access_modes  # ReadWriteMany
  openshift_hosted_registry_storage_nfs_directory # /exports
  openshift_hosted_registry_storage_nfs_options   # "*(rw,root_squash)"
  openshift_hosted_registry_storage_volume_name   # registry
  openshift_hosted_registry_storage_volume_size   # 40Gi
  # etcd
  openshift_hosted_etcd_storage_kind              # nfs
  openshift_hosted_etcd_storage_access_modes      # ["ReadWriteOnce"]
  openshift_hosted_etcd_storage_nfs_directory     # /exports
  openshift_hosted_etcd_storage_nfs_options       # "*(rw,root_squash,sync,no_wdelay)"
  openshift_hosted_etcd_storage_volume_name       # etcd-vol2
  openshift_hosted_etcd_storage_volume_size       # 1G
  openshift_hosted_etcd_storage_labels            # {'storage':'etcd'}
  # disconnected installation
  oreg_url                                        # registry.lab.example.com/openshift3/ose-${component}:${version}
  openshift_examples_modify_imagestreams          # true
  openshift_docker_additional_registries          # registry.lab.example.com
  openshift_docker_blocked_registries             # registry.lab.example.com,docker.io
  # image prefixes
  openshift_web_console_prefix                    # registry.lab.example.com/openshift3/ose-
  openshift_cockpit_deployer_prefix               # 'registry.lab.example.com/openshift3'
  openshift_service_catalog_image_prefix          # registry.lab.example.com/openshift3/ose-
  openshift_service_broker_prefix                 # registry.lab.example.com/openshift3/ose-
  openshift_service_broker_image_prefix           # registry.lab.example.com/openshift3/ose-
  openshift_service_broker_etcd_image_prefix      # registry.lab.example.com/rhel7
  # metrics
  openshift_metrics_install_metrics               # true
```

## 2. Installation process

```bash
sudo yum install atomic-openshift-utils
# Prerequisites - FROM THE DIR WITH 'ansible.cfg'!
ansible-playbook /usr/share/ansible/openshift-ansible/playbooks/prerequisites.yml
# Deploy - FROM THE DIR WITH 'ansible.cfg'!
ansible-playbook /usr/share/ansible/openshift-ansible/playbooks/deplpoy_cluster.yml
```

## 3. Post-installation process

```bash
oc login -u <USER> -p <PASSWORD> --insecure-skip-tls-verify=true
oc get nodes --show labels
ssh master.lab.example.com
sudo -i
oc adm policy add-cluster-role-to-user cluster-admin <USER>
oc explain
```

## 4. Creating a route

### a/ Generate private key

`openssl genrsa -out <hello.apps.lab.example.com.key> 2048`

### b/ Generate CSR (request)

```bash
openssl req -new -key <hello.apps.lab.example.com.key> -out <hello.apps.lab.example.com.csr> \
  -subj "/C=US/ST=NC/L=Raileigh/O=RedHat/OU=RH/CN=hello.apps.lab.example.com"
```

### c/ Generate certificate

```bash
openssl x509 -req -days 365 -in <hello.apps.lab.example.com.csr> -signkey <hello.apps.lab.example.com.key> \
  -out <hello.apps.lab.example.com.crt>
```

### d/ Create secure edge-terminated route

```bash
oc create route edge --service=hello --hostname=hello.apps.lab.example.com --key=hello.apps.lab.example.com \
  --cert=hello.apps.lab.example.com.crt
oc types
oc get routes
oc get route/hello -o yaml
oc get pods -o wide
ssh node1 curl -vvv http://<IP>:8080              # IP from the previous command

# Troubleshooting:
oc describe svc hello-openshift [-n <NAMESPACE>]
oc describe pod <hello-openshift-1-abcd>
oc edit svc hello-openshift
oc edit route hello-openshift
```

## 5. ImageStreams

```bash
oc new-app --name=hello -i php:5.4 \              # -i = imagestream
  http://services/lab/example.com/php-helloworld  # git repository
oc describe is php -n openshift
oc get pods -o wide
oc logs hello-1-build
oc get events
ssh root@master oc get nodes
ssh root@node1 systemctl status atomic-openshift-node
ssh root@node1 systemctl status docker
oc describe is
```

## 6. Common problems

```bash
oc delete all -l app=<node-hello>
oc get all
oc describe pod <hello-1-deploy>
oc get events --sort-by='.metadata.creationTimestamp'
oc get dc <hello> -o yaml
sudo vi /etc/sysconfig/docker
oc rollout latest hellp
oc logs <hello-2-abcd>
pc expose service --hostname=hello.apps.lab.example.com <node-hello>
oc debug pod <PODNAME>
```

## 7. Secrets

```bash
oc create secret generic <mysql> --from-literal='database-user'='mysql' \
  --from-literal='database-password'='r3dh4t'
  --from-literal='database-root-password'='redhat'
oc get secret <mysql> -o yaml
oc new-app --file=mysql.yml
oc port-forward <pod> <local>:<on the pod>        # oc port-forward mysql-1-abcd 3306:3306
```

## 8. User accounts, access

`ssh root@master htpasswd /etc/origin/master/htpasswd <USER>`

### Remove capability to create projects for all regular users

```bash
oc login -u <admin> -p <redhat> <master>
oc adm policy remove-cluster-role-from-group self-provisioner system:authenticated system:authenticated:oauth
```

### Associate user with secure project

```bash
oc login -u <admin> -p <redhat>
oc new-project <secure>
oc project <secure>                               # you don't have to do this, if you then specify -n (last command)
oc policy add-role-to-user edit <user>
oc policy add-role-to-user edit <user> -n <secure># you don't have to do this, if you switched to the namespace already
```

### Pass environment variable to the new app

`oc new-app --name=phpmyadmin --docker-image=registry.lab.example.com/phpmyadmin:4.7 -e PMA_HOST=mysql.secure-review.svc.cluster.local`

### Failed deployment because of the default security

Enable container to run with root privileges:

```bash
oc login -u <admin> -p <redhat>
oc create serviceaccount <phpmyadmin-account>
oc adm policy add-scc-to-user anyuid -z <phpmyadmin-account>
```

### Use & update deployment with the new service account

`oc edit dc/phpmyadmin`                           # or this command:
`oc patch dc/phpmyadmin --patch '{"spec":{"template":{"spec":{"serviceAccountName":"<phpmyadmin-account>"}}}}'`

JSON representation of the above:

```json
{
  "spec": {
    "template": {
      "spec": {
        "serviceAccountName": "<phpmyadmin-account>"
      }
    }
  }
}
```

## 9. Persistent volume

`cat mysqldb-volume.yml`

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: mysqldb-volume
spec:
  capacity:
    storage: 3Gi
  accessModes:
    - ReadWriteMany
  nfs:
    path: /var/export/dbvol
    server: services.lab.example.com
  persistentVolumeReclaimPolicy: Recycle
```

```bash
oc create -f <mysqldb-volume.yml>
oc get pv
oc status -v
oc describe pod <mysqldb>
oc set volume dc/<mysqldb> --add --overwrite --name=<mysqldb-volume-1> -t pvc --claim-name=<mysqldb-pvclaim> \
  --claim-size=<3Gi> --claim-mode=<'ReadWriteMany'>
oc get pvc
```

## 10. Controlling scheduling & scaling

```bash
# Scaling:
oc new-app -o yaml -i php:7.0 http://registry.lab.example.com/scaling > scaling.yml
oc describe dc <scaling> | grep 'Replicas'
oc scale --replicas=5 dc <scaling>
```

```bash
oc get nodes -L region
oc label node <node2.lab.example.com> region=<apps> --overwrite
oc get dc/hello -o yaml > <hello.yml>
```

`hello.yml`

```yaml
nodeSelector:
  region: apps
```

`oc apply -f <hello.yml>`
`oc label node node1.lab.example.com region=apps --overwrite`

### Disable scheduling on node2

`oc adm manage-nmode --schedulable=false <node2.lab.example.com>`

### Delete/drain all pods on node2

`oc adm drain <node2.lab.example.com> --delete-local-data`

### Load Docker image locally

`docker load -i <phpmyadmin-latest.tar>`

### Tag local image ID

`docker tag <123abcdef> <docker-registry-default.apps.lab.example.com/phpmyadmin:4>`
`docker images`

### Login to OpenShift internal image registry

`TOKEN=$(oc whoami -t)`

```bash
docker login -n developer -p ${TOKEN} docker-registry-default.apps.lab.example.com

# Certificate signed by unknown authority:
scp registry.crt root@master:/etc/origin/master/registry.crt
/etc/pki/ca-trust/source/anchors/docker-registry-default.apps.lab.example.com.crt
update-ca-trust
systemctl restart docker
<<RUN DOCKER LOGIN AGAIN>>>
```

## 11. Metrics subsystem

### Verify images required by metrics

`docker-registry-cli <registry.lab.example.com> search <metrics-cassandra> ssl`

```bash
# Output:
openshift3/ose-metrics-hawkular-metrics:v3.9
openshift3/ose-metrics-heapster:v3.9
openshift3/ose-metrics-cassandra:v3.9
openshift3/ose-metrics-recycler:v3.9
```

### Check NFS

`ssh root@services cat /etc/exports.d/openshift-ansible.exports`

### Create PV for NFS share

`cat metrics-pv.yml`

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: metrics
spec:
  capacity:
    storage: 5Gi
  accessModes:
    - ReadWriteOnce                               # Must have this!
  nfs:
    path: /exports/metrics
    server: services.lab.example.com
  persistenVolumeReclaimPolicy: Recycle
```

`oc get pv`

### Add to Ansible inventory file

```ini
[OSEv3:vars]
  openshift_metrics_install_metrics               # true
  openshift_metrics_image_prefix                  # registry.lab.example.com/openshift3/ose-
  openshift_metrics_image_version                 # v3.9
  openshift_metrics_heapster_request_memory       # 300M
  openshift_metrics_hawkular_request_memory       # 750M
  openshift_metrics_cassandra_request_memory      # 750M
  openshift_metrics_cassandra_storage_type        # pv
  openshift_metrics_cassandra_pvc_size            # 5Gi
  openshift_metrics_cassandra_pvc_prefix          # metrics
```

### Run Ansible, verify if it's OK

```bash
oc get pvc -n openshift-infra
oc get pod -n openshift-infra
oc adm diagnostics MetricsApiProxy
```

### Top command as admin

`oc adm top node --heapster-namespace=openshift-infra --heapster-scheme=https`

## 12. Limits

```bash
oc describe node <node1.lab.example.com>
oc describe node <node2.lab.example.com>
# Look for allocated resources (| grep -A 4 Allocated)
# After you deploy new app, allocated resources do NOT change
```

`cat limits.yml`

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: project-limits
spec:
  limits:
    - type: container
      default:
        cpu: 250m
```

`oc describe limits`

`cat quota.yml`

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: project-quota
spec:
  hard:
    cpu: 900m
```

```bash
# Same as:
oc quota project-quota --hard=cpu=900m
oc describe quota
# After you deploy an app, it will consume the project quota
```

```bash
oc describe pod <hello-1-abcdef> | grep -A 2 Requests
# When you scal up and get over the quota, resources will not be created
oc get resourcequota --list-all-quotas
oc get events | grep -i error
oc set resources dc hello --requests=memory=256Mi
# Memory request is not counted against the project quota
```

## 13. Readiness/liveness

```bash
oc status
curl http://probe.apps.lab.example.com/health
curl http://probe.apps.lab.example.com/ready
<<CREATE PROBES IN WEB GUI>>
oc get events --sort-by='.metadata.CreationTimestamp' | grep 'probe failed'
```

## 14. FAQs

### Import the template into OpenShift

`oc apply -n openshift -f <template.yml>`

### Import the Docker image to OpenShift

`oc import-image <stream> --from=registry.lab.example.com/todoapp/todoui --confirm -n <todoapp>`

### Turn service into NodePort

`oc edit svc <hello>`

```yaml
. . .
  ports:
    - name: 8080-tcp
      . . .
      nodePort: 30800
  type: NodePort
. . .
```

### Access shell inside the pod

`oc rsh <hello-1-abcdef>`

### Export resource to YAML

```bash
oc export pod <hello-1-abcdef> > pod.yml
# As template:
oc export svc,dc hello --as-template=docker-hello > template.yml
```

### Configure router to handle wildcard routes

```bash
oc scale dc/router --replicas=0
oc set env dc/router ROUTER_ALLOW_WILDCARD_ROUTES=true
oc scale dc/router --replicas=3
oc expose svc test --wildcard-policy-subdomain --hostname='www.lab.example.com'
```

### Autocomplete

`source /etc/bash_completion.d/oc`


### Troubleshooting policies

```bash
oc describe clusterPolicyBindings :default
oc describe policyBindings :default
```

### Security Context Constraints (SCCs)

```bash
oc get scc
oc create serviceaccount <account>
```

```none
# SCCs:
- anyuid
- hostaccess
- hostmount-anyuid
- nouroot
- privileged
- restricted
```

```none

```

### ConfigMap

`oc create configmap <special-config> --from-literal=serverAddress=172.20.30.40`

### RBAC table

| Name of the role | Permissions |
|------------------|-------------|
|cluster-admin     |superuser    |
|cluster-status    |read-only    |
|edit              |no admin, no quota, no access mgmt |
|basic-user        |read account |
|self-provisioner  |cluster role to create new project(s) |
|admin             |anything     |
