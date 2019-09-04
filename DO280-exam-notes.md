# Red Hat OpenShift Admin I (3.9) DO280/EX280

## Installation - Ansible inventory file & vars

```none
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

```
