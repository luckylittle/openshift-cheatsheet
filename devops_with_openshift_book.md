# Notes from the book DevOps with OpenShift

# By Stefano Picozzi, Mike Hepburn & Noel O'Connor

# O'Reilly 2017

# http://github.com/devops-with-openshift

- OpenShift is a computer software product from Red Hat for container-based software deployment and management. It is a supported distribution of Kubernetes using Docker containers and DevOps tools for accelerated application development.

- OpenShift Origin is the upstream community project used in OpenShift Online, OpenShift Dedicated, and OpenShift Container Platform. Built around a core of Docker container packaging and Kubernetes container cluster management, Origin is augmented by application lifecycle management functionality and DevOps tooling. Origin provides an open source application container platform. All source code for the Origin project is available under the Apache License (Version 2.0) on GitHub.

- OpenShift Online is Red Hat's public cloud application development and hosting service.

- Online offered version 2 of the Origin project source code, which is also available under the Apache License Version 2.0. This version supported a variety of languages, frameworks, and databases via pre-built "cartridges" running under resource-quota "gears". Developers could add other language, database, or components via the OpenShift Cartridge application programming interface. This was deprecated in favour of OpenShift 3 and will be withdrawn on 30th September 2017 for non-paying customers and 31st December 2017 for paying customers.

- OpenShift 3 is built around Kubernetes. It can run any Docker-based container, but Openshift Online is limited to running containers that do not require root.

- OpenShift Dedicated is Red Hat's managed private cluster offering, built around a core of application containers powered by Docker, with orchestration and management provided by Kubernetes, on a foundation of Red Hat Enterprise Linux. It's available on the Amazon Web Services (AWS) and Google Cloud Platform (GCP) marketplaces.

- OpenShift Container Platform (formerly known as OpenShift Enterprise) is Red Hat's on-premises private platform as a service product, built around a core of application containers powered by Docker, with orchestration and management provided by Kubernetes, on a foundation of Red Hat Enterprise Linux.

```
oc whoami

oc status

oc get all

oc describe RESOURCE RESOURCE_NAME

oc export

oc create

oc edit

oc exec POD_NAME <options> <command>

oc rsh POD_NAME <options>

oc delete RESOURCE_TYPE name

oc version

docker version

oc cluster up \
  --host-data-dir=... \
  --host-config-dir=...

oc cluster down

oc cluster up \
  --host-data-dir=... \
  --host-config-dir=... \
  --use-existing-config

oc logout
```

```
oc login -u developer -p developer

oc project myproject

oc new-app --name='cotd' --labels name='cotd' php~https://github.com/devops-with-openshift/cotd.git -e SELECTOR=cats

oc expose service cotd
```

## Create persistent volume

- Supports stateful applications

- Volumes backed by shared storage which are mounted into running pods

- iSCSI, AWS EBS, NFS etc.

## Create volume claim

- Manifests that pods use to retreive and mount the volume into pod at initialization time

- Access modes: REadWriteOnce, REadOnlyMany, ReadWriteMany

## Deployments

### The replication controller

### Deployment strategies

#### Rolling

#### Triggers

#### Recreate

#### Custom

#### Lifecycle hooks

#### Deployment Pod Resources

### Blue-Green deployments

```
oc new-app https://github.com/devops-with-openshift/bluegreen#green --name=green

oc patch route/bluegreen -p '{"spec":{"to":{"name":"green"}}}'

oc patch route/bluegreen -p '{"spec":{"to":{"name":"blue"}}}'
```

### A/B Deployments

```
oc annotate route/ab haproxy.router.openshift.io/balance=roundrobin

oc set route-backends ab cats=100 city=0

oc set route-backends ab --adjust city=+10%
```

### Canary Deployments

### Rollbacks

```
oc rollback cotd --to-version=1 --dry-run

oc rollback cotd --to-version=1

oc describe dc cotd
```


## Pipelines

### Jenkins template

- Comes with all necessary OpenShift plugins (OpenShift login, OpenShift sync, OpenShift pipeline, Kubernetes)

- Comes with example `Jenkinsfile`

```
oc get templates -n openshift | grep jenkins-pipeline-example

oc new-app jenkins-ephemeral # to keep the logs when Jenkins container shuts down

oc get pods

oc new-app jenkins-pipeline-example

oc start-build sample-pipeline

oc get pods
```

- Customizing Jenkins:

```
vim openshift.local.config/master/master-confi.yaml

jenkinsPipelineConfig:
  autoProvisionEnabled: true
  parameters:
    JENKINS_IMAGE_STREAM_TAG: jenkins-2-rhel7:latest
    ENABLE_OAUTH: true
  serviceName: jenkins
  templateName: jenkins-ephemeral
  templateNamespace: openshift
  ```
  
  - Good resource for Jenkinsfiles: https://github.com/fabric8io/fabric8-jenkinsfile-library
  
## Configuration Management

## Secrets

### Creation

- /!\ Maximum size 1MB /!\

```
oc secret new test-secret cert.pem

oc secret new ssl-secret keys=key.pem certs=cert.pem

oc label secret ssl-secret env=test

oc get secrets --show-labels=true

oc delete secret ssl-secret
```

### Using secrets in Pods

- Mounting the secret as a volume

```
oc volume dc/nodejs-ex --add -t secret --secret-name=ssl-secret -m /etc/keys --name=ssl-keys deploymentconfigs/nodejs-ex

oc rsh nodejs-ex-22-8noey ls /etc/keys
```

- Injecting the secret as an env var

```
oc secret new env-secrets username=user-file password=password-file

oc set env dc/nodejs-ex --from=secret/env-secret

oc env dc/nodejs-ex --list
```

## Configuration Maps

- Similar to secrets, but with non-sensitive text-based configuration

### Creation

```
oc create configmap test-config --from-literal=key1=config1 --from-literal=key2=config2 --from-file=filters.properties

oc volume dc/nodejs-ex --add -t configmap -m /etc/config --name=app-config --configmap-name=test-config
```

### Reading config maps

```
oc rsh nodejs-ex-26-44kdm ls /etc/config
```

### Dynamically change the config map

```
oc delete configmap test-config

<CREATE AGAIN WITH NEW VALUES>

<NO NEED FOR MOUNTING AS VOLUME AGAIN>
```

### Mounting config map as ENV

```
oc set env dc/nodejs-ex --from=configmap/test-config

oc describe pod nodejs-ex-27-mqurr
```

## ENV

### Adding

```
oc set env dc/nodejs-ex ENV=TEST DB_ENV=TEST1 AUTO_COMMIT=true

oc set env dc/nodejs-ex --list
```

### Removing

```
oc set env dc/nodejs-ex DB_ENV-
```

## Change triggers

1. `ImageChange` - when uderlying image stream changes

2. `ConfigChange` - when the config of the pod template changes


## Labels & Annotations

1. Label examples: release, environment, relationship, dmzbased, tier, node type, user type
    - Identifying metadata consisting of key/value pairs attached to resources
2. Annotation examples: example.com/skipValidation=true, example.com/MD5checksum-1234ABC, example.com/BUILDDATE=20171217
    - Primarily concerned with attaching non-identifying information, which is used by other clients such as tools or libraries

## OpenShift Builds

### Build strategies

- Source-to-Image (S2I): uses the opensource S2I tool to enable developers to reporducibly build images by layering the application's soure onto a container image

- Docker: using the Dockerfile

- Pipeline: uses Jenkins, developers provide Jenkinsfile containing the requisite build commands

- Custom: allows the developer to provide a customized builder image to build runtime image

### Build sources

- Git

- Dockerfile

- Image

- Binary

### Build Configurations

- contains the details of the chosen build strategy as well as the source

```
oc new-app https://github.com/openshift/nodejs-ex

oc get bc/nodejs-ex -o yaml
```

- unless specified otherwise, the `oc new-app` command will scan the supplied Git repo. If it finds a Dockerfile, the Docker build strategy will be used; otherwise source strategy will be used and an S2I builder will be configured

```
oc new-build openshift/nodejs-010-centos7~https://github.com/openshift/nodejs-ex.git --name='newbuildtest'
```

### S2I

- Components:

1. Builder image - installation and runtime dependencies for the app

2. S2I script - assemble/run/usage/save-artifacts/test/run

- Process:

1. Start an instance of the builder image

2. Retreive the source artifacts from the specified repository

3. Place the source artifacts as well as the S2I scripts into the builder image (bundle into .tar and stream into builder image)

4. Execute assemble script

5. Commit the image and push to OCP registry

- Customize the build process:

1. Custom S2I scripts - their own assemble/run etc. by placing scripts in .s2i/bin at the base of the source code, can also contain environment file

2. Custom S2I builder - write your own custom builder

#### Adding a New Builder Image

#### Building a Sample Application

#### Troubleshooting

- Adding the --follow flag to the start-build command

- oc get builds

- oc logs build/test-app-3

- oc set env bc/test-app BUILD_LOGLEVEL=5 S2I_DEBUG=true

## Application Management

- Operational layers:

1. Operating system infrastructure operations - compute, network, storage, OS

2. Cluster operations - cluster managemebt OpenShift/Kubernetes

3. Application operations - deployments, telemetry, logging

### Integrated logging

- the EFK (Elasticsearch/Fluentd/Kibana) stack aggregates logs from nodes and application pods

```
oc cluster up --logging=true
```

### Simple metrics

- the Kubelet/Heapster/Cassandra and you can use Grafana to build dashboard

```
oc cluster up --metrics=true
```

### Resource scheduling

- default behavior:

1. best effor isolation = no primises what resources can be allocated for your project

2. might get defaulted values

3. out of memory killed randomly

4. might get CPU starved (wait to schedule your workload)

### Resource quotas

- hard constraints how much memory/CPU your project can consume

```
oc login -u developer -p developer

oc new-project development --display-name='Development' --description='Development'

oc login -u system:admin

oc create -n development -f <YAML FILE HERE kind: ResourceQuota>

oc describe quota -n development
```

### Limit ranges

- mechanism for specifying default project CPU and memory limits and requests

```
oc get limits -n development

oc describe limits core-resource-limits -n development
```

### Multiproject quota

- you may use project labels or annotations when creating multiproject spanning quotas

```
oc login -u system:admin

oc create clusterquota for-user-developer --project-annotation-selector openshift.io/requester=developer --hard pods=8

oc login -u developer -p developer

oc describe AppliedClusterResourceQuota
```

### Auto scaling of the pod

```
oc autoscale dc myapp --min 1 --max 4 --cpu-percent=75

oc get hpa myapp
```
