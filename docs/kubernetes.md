## Quick Reference

### Minikube

- starts minikube
    ```
    minikube start
    ```
- stops the minikube virtual machine
    ```
    minikube stop
    ```
- completely wipe away the minikube image. Also you can delete all files in <home>/.minikube and <home>/.kube.
    ```
    minikube delete
    ```
- find out the required environment variables to connect to the docker daemon running in minikube
    ```
    minikube env
    ```
- find out the ip address of minikube. Needed for browser access.
    ```
    minikube ip
    ```

### Kubectl

- list all namespaces
    ```
    kubectl get ns
    ```
- list all objects that you’ve created. Pods at first, later, ReplicaSets, Deployments and Services
    ```
    kubectl get all
    ```
- either creates or updates resources depending on the contents of the yaml file
    ```
    - kubectl apply –f <yaml file>
    ```
- apply all yaml files found in the current directory 
    ```
    kubectl apply –f .
    ```
- gives full information about the specified pod
    ```
    kubectl describe pod <name of pod>
    ```
- gives full information about the specified service
    ```
    kubectl describe svc <name of pod>
    ```
- view pod logs
    ```
    kubectl logs {pod-name}
    ```
- execute the specified command in the pod’s container. Doesn’t work well in Cygwin.
    ```
    kubectl exec –it <pod name> <command>
    ```
- get all pods or services. Later in the course, replicasets and deployments.
    ```
    kubectl get (pod | po | service | svc | rs | replicaset | deployment | deploy)
    ```
- get all pods and their labels
    ```
    kubectl get po --show-labels
    ```
- get all pods matching the specified name:value pair
    ```
    kubectl get po --show-labels -l {name}={value}
    ```
- delete the named pod. Can also delete svc, rs, deploy
    ```
    kubectl delete po <pod name>
    ```
- delete all pods (also svc, rs, deploy)
    ```
    kubectl delete po --all
    ```

### Deployment Management

- get the status of the named deployment
    ```
    kubectl rollout status deploy <name of deployment>
    ```
- get the previous versions of the deployment
    ```
    kubectl rollout history deploy <name of deployment>
    ```
- go back one version in the deployment. Also optionally --to-revision=\<revision_number\> We recommend this is used only in stressful emergency situations! Your YAML will now be out of date with the live deployment! 
    ```
    kubectl rollout undo deploy <name of deployment>
    ```

### Volumes 

- list PersistentVolumeClaims
    ```
    kubectl get pvc
    ```

### kops 

- Create cluster
    ```
    kops create cluster --zone eu-west-2a,eu-west-2b ${NAME}
    ```
- Edit instance-group configuration
    ```
    kops edit ig
    ```
- Update cluster
    ```
    kops update cluster ${NAME} --yes
    ```
- Validate cluster
    ```
    kops validate cluster
    ```
- Delete cluster
    ```
    kops delete cluster --name ${NAME} --yes
    ```

## Yamls

### Pod

- The basic execution unit of a Kubernetes application--the smallest and simplest unit in the Kubernetes object model that you create or deploy. 
- A Pod represents processes running on your cluster.
- Init container
  - Run before the app containers are started.
  - Init containers always run to completion.
  - Each init container must complete successfully before the next one starts.
  - If a Pod's init container fails, Kubernetes repeatedly restarts the Pod until the init container succeeds. However, if the Pod has a restartPolicy of Never, Kubernetes does not restart the Pod.
- <https://kubernetes.io/docs/concepts/workloads/pods/pod-overview/>
- <https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#pod-v1-core>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-example
spec:
  containers:
  - name: ubuntu
    image: ubuntu:trusty
    command: ["echo"]
    args: ["Hello World"]
```

### ReplicaSet 

- Maintain a stable set of replica Pods running at any given time. 
- As such, it is often used to guarantee the availability of a specified number of identical Pods
- <https://kubernetes.io/docs/concepts/workloads/controllers/replicaset/>
- <https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#replicaset-v1-apps>

```yaml
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  # Unique key of the ReplicaSet instance
  name: replicaset-example
spec:
  # 3 Pods should exist at all times.
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      # Run the nginx image
      - name: nginx
        image: nginx:1.14
```

### Deployment 

- Deployment provides declarative updates for Pods and ReplicaSets.
- You describe a desired state in a Deployment, and the Deployment Controller changes the actual state to the desired state at a controlled rate.
- <https://kubernetes.io/docs/concepts/workloads/controllers/deployment/>
- <https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#deployment-v1-apps>
  
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  # Unique key of the Deployment instance
  name: deployment-example
spec:
  # 3 Pods should exist at all times.
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        # Apply this label to pods and default
        # the Deployment label selector to this value
        app: nginx
    spec:
      containers:
      - name: nginx
        # Run this image
        image: nginx:1.14
```

### DaemonSet

- A DaemonSet ensures that all (or some) Nodes run a copy of a Pod. 
- As nodes are added to the cluster, Pods are added to them. As nodes are removed from the cluster, those Pods are garbage collected.
  - running a cluster storage daemon on every node
  - running a logs collection daemon on every node
  - running a node monitoring daemon on every node
- <https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/>
- <https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#daemonset-v1-apps>

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  # Unique key of the DaemonSet instance
  name: daemonset-example
spec:
  selector:
    matchLabels:
      app: daemonset-example
  template:
    metadata:
      labels:
        app: daemonset-example
    spec:
      containers:
      # This container is run once on each Node in the cluster
      - name: daemonset-example
        image: ubuntu:trusty
        command:
        - /bin/sh
        args:
        - -c
        # This script is run through `sh -c <script>`
        - >-
          while [ true ]; do
          echo "DaemonSet running on $(hostname)" ;
          sleep 10 ;
          done
```

### Service

- <https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#service-v1-core>

```yaml
kind: Service
apiVersion: v1
metadata:
  # Unique key of the Service instance
  name: service-example
spec:
  ports:
    # Accept traffic sent to port 80
    - name: http
      port: 80
      targetPort: 80
  selector:
    # Loadbalance traffic across Pods matching
    # this label selector
    app: nginx
  # Create an HA proxy in the cloud provider
  # with an External IP address - *Only supported
  # by some cloud providers*
  type: LoadBalancer
```

### Volume and VolumeMounts

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pv-recycler
  namespace: default
spec:
  restartPolicy: Never
  volumes:
  - name: vol
    hostPath:
      path: /any/path/it/will/be/replaced
  containers:
  - name: pv-recycler
    image: "k8s.gcr.io/busybox"
    command: ["/bin/sh", "-c", "test -e /scrub && rm -rf /scrub/..?* /scrub/.[!.]* /scrub/*  && test -z \"$(ls -A /scrub)\" || exit 1"]
    volumeMounts:
    - name: vol
      mountPath: /scrub
```

### PersistentVolumeClaims

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: my-pvc
spec:
  storageClassName: my-ssd-local-storage
  # Find matching storage class
  accessModes:
    - ReadWriteOnce
    # Find matching access mode
  resources:
    requests:
      storage: 8Gi
      # Find 8Gi of storage 
```

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: my-local-storage
spec:
  storageClassName: my-ssd-local-storage
  capacity:
    storage: 8Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: "/mnt/somedir"
    type: DirectoryOrCreate
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  containers:
    - name: myfrontend
      image: nginx
      volumeMounts:
      - mountPath: "/var/www/html"
        name: mypd
  volumes:
    - name: mypd
      persistentVolumeClaim:
        claimName: my-pvc
```

### StorageClass and Binding
- Change reclaim policy as required 

```yaml
# What do want?
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: mongo-pvc
spec:
  storageClassName: cloud-ssd
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 7Gi
---
# How do we want it implemented
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: cloud-ssd
provisioner: kubernetes.io/aws-ebs
parameters:
  type: gp2
```

### StatefulSet Set

- StatefulSet is the workload API object used to manage stateful applications.
  - Stable, unique network identifiers.
  - Stable, persistent storage.
  - Ordered, graceful deployment and scaling.
  - Ordered, automated rolling updates.
- Like a Deployment, a StatefulSet manages Pods that are based on an identical container spec. 
- Unlike a Deployment, a StatefulSet maintains a sticky identity for each of their Pods.
- These pods are created from the same spec, but are not interchangeable: 
  - Each has a persistent identifier that it maintains across any rescheduling.
- <https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/>


### RBAC

- <https://kubernetes.io/docs/reference/access-authn-authz/rbac/>
- Kind - `Role` -> `ClusterRole`to grant cluster-wide permissions.
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""] # "" indicates the core API group
  resources: ["pods"]
  verbs: ["get", "watch", "list"]
```
```yaml
apiVersion: rbac.authorization.k8s.io/v1
# This role binding allows "jane" to read pods in the "default" namespace.
# You need to already have a Role named "pod-reader" in that namespace.
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
# You can specify more than one "subject"
- kind: User
  name: jane # "name" is case sensitive
  apiGroup: rbac.authorization.k8s.io
roleRef:
  # "roleRef" specifies the binding to a Role / ClusterRole
  kind: Role #this must be Role or ClusterRole
  name: pod-reader # this must match the name of the Role or ClusterRole you wish to bind to
  apiGroup: rbac.authorization.k8s.io
```

## Cloud Deployments 
 
**Kops**

- <https://kops.sigs.k8s.io/>
- <https://kops.sigs.k8s.io/getting_started/commands/>

## Notes 

- Service
  - Pods are not visible outside k8s cluster
  - K8s service is a long running object with IP address and stable fixed port usable to expose Pods out of k8s cluster
  - Pod can have "Label" (key value pairs)
  - Service can have "Selector" (key value pairs)
  - Service will look for any matching key-value pairs when binding a service to a pod (selector / label)
  - Service Types:
    - NodePort 
      - Expose a port through the node 
      - Port needs to be greater than 30,000
      - Configure `port` and `nodeport` 
    - ClusterIP 
      - Internal service / not exposed to external traffic but exposed to internal nodes
    - LoadBalancer
- Pod may die for many reasons:
  - If pod take too many resources
  - If node failed (all pods in that node die)
- ReplicaSets 
  - Add replica count into `pod definition`
  - Change kind to `ReplicaSet`
  - Nest pod definition in `template`  `spec` attribute
  - Remove `pod names`
  - Add `selector` block (similar to `services`)
- Deployment 
  - Automatic rolling update with rollbacks
- Networking 
  - Service Discovery
    - Same Pod - can be accessed via `localhost`
    - Kube-dns - Resolve service name to IP address
  - Namespaces 
    - Partitioning resources into separate areas
    - `kubectl get ns` get list of namespaces 
    - `kubectl get all -n kube-system` list resources from a namespace
  - `FQDN` -> `database` -> `database.mynamespace` -> `database.mynamespace.svc.cluster.local` (last part is appended by DNS)
    - Check `/etc/resolve.conf`
- Expand memory:
  - `minikube stop`
  - `minikube delete`
  - `rm -rf ~/.kube` and `rm -rf ~/.minikube`
  - `minikube start --memory 4096`
- Microservices 
  - changing one part is hard without affecting other
  - complications of release coordination (big bang releases)
  - shared global databases (integration databases)
  - microservices as extreme form of modularity 
    - no direct communication in between
    - interfaces for communication 
    - totally independent 
    - limit to one specific area of business function
    - highly cohesive and loosely coupled
    - database is split 
    - Domain-driven Design (Eric Evans) - Bounded Context
    - <https://github.com/DickChesterwood/k8s-fleetman>
    - need api gateway to expose backend functions (microservices)
      - single point of entry to system
      - <https://microservices.io/patterns/apigateway.html> 
- Common Cluster Configurations: <https://github.com/kubernetes/kubernetes/tree/master/cluster/addons>
- ElasticStack + (LogStash / FluentD)
- Helm - Package management for k8s
  - `helm init`
  - `helm version`
  - <https://github.com/helm/charts>
  - `helm repo update`
  - `helm install stable/mysql --set mysqlPassword=example --name my-mysql`
  - Fix permissions:
    ```bash
    kubectl create serviceaccount --namespace kube-system tiller
    kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
    kubectl patch deploy --namespace kube-system tiller-deploy -p '{"spec":{"template":{"spec":{"serviceAccount":"tiller"}}}}' 
    ```
- Prometheus / Grafana (UI)
  - `helm install stable/prometheus-operator --name my-monitoring --namespace monitoring`
  - To see how this works `kops edit cluster --name prometheus-oper-prometheus` change type to `LoadBalancer` and access UI(9090/graph))
  - To get a full set of data from Prometheus:
    ```bash
    kops edit cluster --name ${NAME}
    kubelet:
      anonymousAuth: false    
      authenticationTokenWebhook: true    
      authorizationMode: Webhook
    kops update cluster --yes
    kops rolling-update cluster --yes 
    ```
  - `prometheus-operator" failed: rpc error: code = Canceled` <https://github.com/helm/helm/issues/6130>
    - `helm del --purge monitoring`
    - `helm install --name monitoring --namespace monitoring stable/prometheus-operator --set prometheusOperator.createCustomResource=false`
  - `AlertManager` over `/api`
    - Dead man's switch - Constantly alerting. Stops if an alert is fired (or Prometheus is down)
  - `Slack` integration 
    - Incoming web-hook
    - Listen for Dead man's switch
    - <https://prometheus.io/docs/alerting/latest/configuration/>
    - `alertmanager.yaml`
        ```yaml
        global:
        slack_api_url: '<<add your slack endpoint here>>'
        route:
        group_by: ['alertname']
        group_wait: 5s
        group_interval: 1m
        repeat_interval: 10m
        receiver: 'slack'

        receivers:
        - name: 'slack'
        slack_configs:
        - channel: '#alerts'
            icon_emoji: ':bell:'
            send_resolved: true
            text: "<!channel> \nsummary: {{ .CommonAnnotations.message }}\n"
        ```
    - `kubectl logs -n monitoring-namespace  kube-prometheus`
    - `kubectl logs -n monitoring-namespace  kube-prometheus -c alertmanager`
    - remove existing secret for the config file and set a new secret (`alertmanager-kube-prometheus`)
- Requests and Limits
  - Allow cluster manager to make intelligent decisions 
  - If memory limit reached -> pod remain running, container restart
  - If cpu limit reached -> cpu clamped/throttled (will not be allowed to go over)
    ```yaml
    kind: Pod
    spec:
    containers:
    - name: db
        resources:
        requests:
            memory: "64Mi"
            cpu: "250m"
        limits:
            memory: "128Mi"
            cpu: "500m"
    ``` 
- Metrics 
  - Enable metrics server: `minikube addons list` `minikube addons enable metrics-server`
  - View stats: `kubectl top pod` `kubectl top node`
- Dashboard
  - `minikube dashboard`
- Horizontal Pod Autoscaling (HPA)
  - <https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/>
  - <https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale-walkthrough/>
  - `kubectl autoscale deployment example-deployment --cpu-percent 400 --min 1 --max 5` (relative to the request)
  - `kubectl get hpa`
  - `kubectl describe hpa`
  - `kubectl get hpa -o yaml`
    ```yaml
    behavior:
    scaleDown:
        policies:
        - type: Pods
        value: 4
        periodSeconds: 60
        - type: Percent
        value: 10
        periodSeconds: 60
    ```
- Readiness Probe / Liveness Probe
  - <https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/>
  - `readiness probes` - to decide when the container is available for accepting traffic
  - `startup probe` - with `failureThreshold * periodSeconds` long enough to cover the worse case startup time. deal with legacy applications that might require an additional startup time on their first initialization.
  - `liveness probes` - to know when to restart a container (!live = restart)
- QoS and Evection 
  - <https://kubernetes.io/docs/concepts/scheduling-eviction/kube-scheduler/>
  - A scheduler watches for newly created Pods that have no Node assigned. 
  - For every Pod that the scheduler discovers, the scheduler becomes responsible for finding the best Node for that Pod to run on. 
  - QoS
    - <https://kubernetes.io/docs/tasks/configure-pod-container/quality-service-pod/>
    - Guaranteed - Both Limit and Request defined
    - Burstable - Only Request is defined
    - BestEffort - No limit or request defined 
    - `kubectl describe pod` shows QoS class
  - Evicted based on QoS
- Pod Priorities    
  - <https://kubernetes.io/docs/concepts/configuration/pod-priority-preemption/>
  - Priority indicates the importance of a Pod relative to other Pods. 
  - If a Pod cannot be scheduled, the scheduler tries to preempt (evict) lower priority Pods to make scheduling of the pending Pod possible.
  - Only `Pod-Priority` is used in scheduling new pods 
  - During evection only `QoS` is considered first and then `Pod-Priority`
- RBAC
  - `kubectl get role`
  - `kubectl get rolebinding`
  - Super-user
    - Create OS user
    - In k8s create a new namespace `kubectl create ns playground`
    - `kubectl config view`. Copy API LB endpoint URL. 
    - X.509
      - API only accept requests signed by `CA` within the k8s cluster
      - Create private-key: `openssl genrsa -out private-key-username.key 2048`
      - CSR: `openssl req -new -key private-key-username.key -out req.csr --subj "/CN=username/O=groupname"`
      - `aws s3 cp s3://storage-name/example.local/pki/private/ca/<number>.key kubernetes.key` 
      - `aws s3 cp s3://storage-name/example.local/pki/issued/ca/<number>.crt kubernetes.crt` 
      - `openssl x509 -req -in req.csr -CA kubernetes.crt -CAkey kubernetes.key -CAcreateserial -out username.crt -days 365`
      - Install new certificate with:
        - `cp username.crt /home/.certs/`
        - `cp private-key-username.key /home/.certs/`
        - `cp kubernetes.crt /home/.certs/`
        - `chown -R username:username /home/username/certs`
    - Define `Role` and `RoleBinding` (to bind role to user).
  - New user do:
    - `kubectl config set-credential username --client-certificate=username.crt --client-key=private-key-username.key`
    - `kubectl config set-cluster example.local --certificate-authority=kubernetes.crt`
    - `kubectl config set-cluster example.local --server=<api-lb_url>`
    - Now new user can: `kubectl config set-context mycontext --user my-user-name --cluster example.local` <https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/>
    - Check config with `kubectl config view`
    - `kubectl config use-context mycontext`
    - Now new user can `kubectl get all`
  - Only allowed to access the namespace defined in `role`.
  - If all-namespaces should be visible use `ClusterRole` and `ClusterRoleBinding`.
    - Grant limited permission across cluster. Then use `Role` section to grant wider permissions on own-cluster. 
  - `ServiceAccount` in `RoleBinding` is used to grant access to one pod from another. 
- Secrets 
  - `kubectl get secrets` 
  - `kubectl get secret -n monitoring example -o json`
  - `kubectl delete secret -n monitoring example -o json`
  - `kubectl create secret -n monitoring example --from-file=example.yaml`

```
- OpenFaaS Kubeless OpenWisk
- GitLab TravisCI CircleCI
- Promethius Fluentd OpenTracing Jeager 
- Istio LinkerD Consul
- Teraform Helma
```

## Tools 

- Kubernetes RBAC static Analysis & visualisation tool: <https://github.com/appvia/krane>

## Security Validations 

- For internal services, use `ClusterIP` service-type. (instead of `NodePort`)
- In production all use `ClusterIP` ??
- Are pods stateless?
- Are resource requests and limits defined properly.
  - `kubectl describe node minikube` (cluster node). `Allocatable` and `Capacity`. 
- If < Java 10 is used 1/4 of RAM is taken for Xmx by default (`-Xmx50m`)
- Readiness Probe / Liveness Probe defined properly
- `kubectl config view --minify` to get password of cluster admin user/password. usable to login to cluster API and all services deployed in the cluster including `AlertManager`:
  - `/api/v1/namespaces/`
  - `/api/v1/namespaces/monitoring/services`
  - `/api/v1/namespaces/monitoring/services/alert-manager-operated:9093/proxy`
- Prometheus: <https://prometheus.io/docs/operating/security/>
- Audit RBAC configuration
  - API groups are defined properly without using `*`
  - Check `ClusterRole` for cluster wide permissions 
- K8s API only accepts requests signed by `CA` within the k8s cluster
- Make sure cluster key is stored securely. 
  - `kops`: `KOPS_STATE_STORE` (s3 bucket) contains this. `cluster_folder/pki/private/ca/<number>.key` and `pki/issued/ca/<number>.crt`.
    - `aws s3 ls s3://storage-name/example.local/pki/private/ca/<number>.key`
    - `aws s3 cp s3://storage-name/example.local/pki/private/ca/<number>.key kubernetes.key` 
    - `aws s3 cp s3://storage-name/example.local/pki/issued/ca/<number>.crt` 


## Cluster API 

- Bring declarative k8s style APIs to cluster creation, configuration and management.

## New References

- Understanding Kubernetes limits and requests by example: <https://sysdig.com/blog/kubernetes-limits-requests/>
- Understanding Kubernetes pod evicted and scheduling problems: <https://sysdig.com/blog/kubernetes-pod-evicted/>
- How to troubleshoot Kubernetes OOM and CPU Throttle: <https://sysdig.com/blog/troubleshoot-kubernetes-oom/>