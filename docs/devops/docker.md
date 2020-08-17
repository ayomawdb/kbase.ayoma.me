## Quick Reference

- Open Container Spec - Labels: <https://github.com/opencontainers/runtime-spec>
  - Add labels at end - so that full image build is not required to change

### Manage images

- download an image from DockerHub: 
    ```bash
    docker image pull <image name>
    ```
- list all local images: 
    ```
    docker image ls Chapter 5
    ```
- build an image with a tag (note the dot!): 
    ```
    docker image build -t <image name>
    ```
- publish an image to dockerhub: 
    ```
    docker image push <image name>
    ```
- tag an image - either alias an exisiting image or apply a :tag to one: 
    ```
    docker image tag <image id> <tag name>
    ```

### Manage Containers 

- run a container from an image, publishing the specified ports: 
    ```
    docker container run -p <public port>:<container port> <image name>
    ```
- list all containers, even the stopped ones: 
    ```
    docker container ls -a
    ```
- stop a running container: 
    ```
    docker container stop <container id>
    ```
- restart a stopped container: 
    ```
    docker container start <container id> 
    ```
- remove a stopped container: 
    ```
    docker container rm <container id> 
    ```
- remove all stopped containers: 
    ```
    docker container prune
    ```
- run a container with interactive terminal: 
    ```
    docker container run -it  <image name> 
    ```
- run a container detached (or in a daemon like way): 
    ```
    docker container run -d  <image name>
    ```
- run a command in a container: 
    ```
    docker container exec -it <container id> <command>
    ```
- special form of the above, runs a bash shell, connected to your local terminal (your distro needs to have bash, alpine will require /bin/sh): 
    ```
    docker container exec -it <container id> bash
    ```
- Follow the log (STDIN/System.out) of the container: 
    ```
    docker container logs -f <container id>
    ```
- Take a snapshot image of a container: 
    ```
    docker container commit -a "author" <container id> <image name>
    ```
- Pause: `docker pause`
- Unpause: `docker unpause`

### Manage your (local) Virtual Machine

- Find the IP address of your VirtualMachine, required for Docker Toolbox users only: 
    ```
    docker-machine ip
    ```

### Manage Networks

- list all networks (bridge/host/none/etc.): 
    ```
    docker network ls
    ```
- create a network using the bridge driver: 
    ```
    docker network create <network name>
    ```
- Inspect the complete network:
    ```
    docket network inspect <network name>
    ```
- Link two containers (this is legacy):   
    ```
    docker container run ... --link <container-name-to-link-with> <image-name>
    ```
- New way of linking two containers (using Docker Compose is easier):
    ```
    sudo docker network create mynetwork
    sudo docker container run ... --network mynetwork <image-name>
    ```

### Manage Volumes

- list all volumes: 
    ```
    docker volume ls
    ```

- delete all volumes that are not currently mounted to a container: 
    ```
    docker volume prune
    ```
- inspect a volume (can find out the mount point, the location of the volume on the host system) 
    ```
    docker volume inspect <volume name>
    ```
- remove a volume: 
    ```
    docker volume rm <volume name>
    ```

### Docker Compose

- process the default docker-compose.yaml file, starting any containers as required. If containers are already running they are ignored, meaning this command also serves as a "redeploy": 
    ```
    docker-compose up
    ```
- run containers in the detached state. Note the order of the command line arguments!: 
    ```
    docker-compose up -d
    ```
- follow the log for the specified service. Omit the -f to tail the log: 
    ```
    docker-compose logs -f <service name>
    ```
- stop all the containers (services) listed in the default compose file: 
    ```
    docker-compose down
    ```
- Validation: `docker-compose config`
- Images: `docker-compose images`
- Processes: `docker-compose top`
- Pause: `docker-compose pause`
- Unpause: `docker-compose unpause`

### Manage a Swarm

- Switch the machine into Swarm mode. We didn't cover how to stop swarm mode: docker swarm leave --force: 
    ```
    docker swarm init (--advertise-addr <ip address>)
    ```
- Start a service in the swarm. The args are largely the same as those you will have used in docker container run: 
    ```
    docker service create <args>
    ```
- Create a network suitable for using in a swarm: 
    ```
    docker network create --driver overlay <name>
    ```
- List all services: 
    ```
    docker service ls
    ``` 
- List all nodes in the swarm: 
    ```
    docker node ls 
    ```
- Follow the log for the service. This feature is a new feature in Docker and may not be available on your version (especially if using Linux Repository Packages): 
    ```
    docker service logs -f <service name>
    ```
- List full details of the service - in particular the node on which it is running and any previous failed containers from the service: 
    ```
    docker service ps <service name>
    ```
- Get a join token to enable a new node to connect to the swarm, either as a worker or manager: 
    ```
    docker swarm join-token <worker|manager>
    ```

### Manage Stacks

- list all stacks on this swarm: 
    ```
    docker stack ls
    ```
- deploy (or re-deploy) a stack based on a standard compose file: 
    ```
    docker stack deploy -c <compose file> <stack name>
    ```
-  delete a stack and its corresponding services/networks/etc: 
    ```
    docker stack rm <stack name>
    ```

### System

- Disk usage
    ```
    docker system df
    ```
- Events
    ```
    docker system events
    ```
- System wide information
    ```
    docker system info
    ```
- Remove unused ata
    ```
    docker system prune
    ```

### Statistics 

- Container statistics 
    ```
    docker stats <id>
    ```

## Internals

- History <www.slideshare.net/jkshah/postgresql-and-linux-containers>
  - Chroot circa 1982
  - FreeBSD Jails circa 2000
  - Solaris Zones circa 2004
  - Meiosys - MetaClusters with Checkpoint/Restore 2004-05
  - Linux OpenVZ circa 2005 (not in mainstream Linux)
  - AIX WPARs circa 2007
  - LXC circa 2008
  - Systemd-nspawn circa 2010-2013
  - Docker circa 2013
    - built on LXC
    - moved to libcontainer (March 2014)
    - appC (CoreOS) announced (December 2014)
    - Open Containers standard for convergence with Docker Announced (June 2015)
    - moved to runC (OCF compliant) (July 2015)
- Namespaces
  - References
    - [Namespaces in operation, part 1: namespaces overview](https://lwn.net/Articles/531114/)
    - [Namespaces in operation, part 2: the namespaces API](https://lwn.net/Articles/531381/)
    - [Namespaces in operation, part 3: PID namespaces](https://lwn.net/Articles/531419/)
    - [Namespaces in operation, part 4: more on PID namespaces](https://lwn.net/Articles/532748/)
    - [Namespaces in operation, part 5: User namespaces](https://lwn.net/Articles/532593/)
    - [Namespaces in operation, part 6: more on user namespaces](https://lwn.net/Articles/540087/)
    - [Namespaces in operation, part 7: Network namespaces](https://lwn.net/Articles/580893/)
    - [Mount namespaces and shared subtrees](https://lwn.net/Articles/689856/)
    - [Mount namespaces, mount propagation, and unbindable mounts](https://lwn.net/Articles/690679/)
    - [A deep dive into Linux namespaces](http://ifeanyi.co/posts/linux-namespaces-part-1/)
    - [Demystifying namespaces and containers in Linux](https://opensource.com/article/19/10/namespaces-and-containers-linux)
    - [Separation Anxiety: A Tutorial for Isolating Your System with Linux Namespaces](https://www.toptal.com/linux/separation-anxiety-isolating-your-system-with-linux-namespaces)
  - Syscalls 
    - clone() 
      - creating a namespace
      - `int clone(int (*child_func)(void *), void *child_stack, int flags, void *arg);` is more general version of `fork()`
      -  If one of the CLONE_NEW* bits is specified in the call, then a new namespace of the corresponding type is created, and the new process is made a member of that namespace
    - setns() 
      - Keeping a namespace open when it contains no processes
      - disassociates the calling process from one instance of a particular namespace type and reassociates the process with another instance of the same namespace type
      - `int setns(int fd, int nstype);`
      - usable to join a given ns and execute command there
    - unshare()
      - creates the new namespaces specified by the CLONE_NEW* bits in its flags argument and makes the caller a member of the namespaces
      - main purpose is to isolate namespace (and other) side effects without having to create a new process or thread (as is done by clone()).
      - `clone(..., CLONE_NEWXXX, ....);` ~= `if (fork() == 0) unshare(CLONE_NEWXXX);`
  - Syscalls use constants:
    - CLONE_NEWIPC
    - CLONE_NEWN
    - CLONE_NEWNET
    - CLONE_NEWPID
    - CLONE_NEWUSER
    - CLONE_NEWUTS
  - `/proc/<PID>/ns` directory that contains one file for each type of namespace
  - Demo Separation with Docker: <https://www.netmanias.com/en/post/blog/13392/sdn-nfv/docker-internals>
- cgroups <http://docker-saigon.github.io/post/Docker-Internals/#how:cb6baf67dddd3a71c07abfd705dc7d4b>
  - allow you to do accounting on resources used by processes
    - a little bit of access control on device nodes 
    - and other things such as freezing groups of processes
  - Managing with `Systemd`
    - Set `ControlGroupAttribute`
    - `ControlGroupAttribute=memory.swappiness 70`
    - `systemctl set-property <group> CPUShares=512`
    - `systemctl show <group>`
  - Internals:
    - `mkdir /sys/fs/cgroup/memory/somegroup/subcgroup`
    - Move process: `echo $PID > /sys/fs/cgroup/.../tasks`
  - cgroups consist of one hierarchy (tree) per resource (cpu, memory, …). can create sub groups for each hierarchy. 
    ```
    cpu                      memory
    ├── batch                ├── 109
    │   ├── hadoop           ├── 88 <
    │   │   ├── 88 <         ├── 25
    │   │   └── 109          ├── 26
    └── realtime             └── databases
        ├── nginx                ├── 1008
        │   ├── 25               └── 524
        │   └── 26          
        ├── postgres 
        │   ├── 524  
        └── redis    
            └── 1008 
    ```
    - memory
      - accounting
        - file pages: loaded from disk (can be discarded since it's anyway in the disk)
        - anonymous pages: memory that does not correspond to anything on disk
        - 2 pools for all pages:
          - Active
          - Inactive pages
      - limits
        - Hard limits: If the group goes above its hard limit, the group gets killed
        - Soft limits: not enforced. except when the system starts to run out of memory. The more a process goes over its soft limit, the higher the chance pages get reclaimed for its group
        - Kind of memories the limit can be applied:
          - physical memory
          - kernel memory: to avoid processes abusing the kernel to allocate memory
          - total memory
        - oom-notifier - mechanism to give control to a user program to handle a group going over its limits by freezing the processes in the group and notifying user space
        - Overhead - Each time the kernel gives or takes a page to or from a process, counters are updated.
      - CPU cgroup
        - allows to set weights - not limits (On an idle host a container with low shares will still be able to use 100% of the CPU)
      - CPUSet cgroup
        - Bind group to specific CPU
        - For:
          - Real Time applications
          - NUMA systems with localized memory per CPU
      - BlkIO cgroup
        - Measure & Limit amount of blckIO by group
      - net_cls and net_prio cgroup
        - traffic control 
      - Devices cgroup
        - Controls which group can read/write access devices.
        - Usually containers access: /dev/{tty,zero,random,null}
        - `/dev/net/tun` if you want to do anything with vpn’s inside a container without polluting the host
        - `/dev/fuse` custom filesystems in a container
        - `/dev/kvm` to allow virtual machines to run inside a container
        - `/dev/dri` & `/dev/video` for GPU access in containers - (see NVIDIA/nvidia-docker).
      - Freezer cgroup
        - Freeze a whole group without sending SIGSTOP/SIGCONT to the group
    - notifications 
- IPTables (networking)
  - Virtual switches in the linux kernel
  - Linux Bridge is a kernel module
  - Administered using the `brctl`
  - Network shaping and bandwidth control for Linux containers: [tc](http://www.lartc.org/manpages/tc.txt)
    - Demo using two hosts at: <http://docker-saigon.github.io/post/Docker-Internals/#how:cb6baf67dddd3a71c07abfd705dc7d4b>
    - Linux bridges & IPtable rules: `brctl show` `sudo iptables -nvL`
    - port has been opened for each port exposed: `ss -an | grep LISTEN`
    - userland docker-proxy process: `ps -Af | grep proxy`
    - Memory usage by these proxies: `ps -o pid,%cpu,%mem,sz,vsz,cmd -A --sort -%mem | grep proxy`
    - Name resolution: `docker exec host2 cat /etc/resolv.conf`
    - DNS process injected into the container: `docker exec -it host2 netstat -an`
    - exposing additional ports: forward packets from port 8001 on your host to port 8000 on the container: `iptables -t nat -A DOCKER -p tcp --dport 8001 -j DNAT --to-destination ${CONTAINER_IP}:8000`
    - cgroup setup: `sudo systemd-cgls`
- Union File Systems (UnionFS) - AUFS, btrfs, vfs, and devicemapper
  - Docker engine prepares the `rootfs` & uses `chroot` for the container filesystem isolation (similar to LXC)
  - Storage plugins: <https://docs.docker.com/storage/storagedriver/>
    - OverlayFS (CoreOS)
    - AUFS (Ubuntu)
    - device mapper (RHEL)
    - btrfs (next-gen RHEL)
    - ZFS (next-gen Ubuntu releases)
  - Union File Systems provide the following features for storage:
    - Layering
    - Copy-On-Write
      - significantly speed up the preparation of the `rootfs`
      - LXC would create a full copy of FileSystem when creating a container
    - Caching
    - Diffing
- Container Runtimes: <http://docker-saigon.github.io/post/Docker-Internals/>
  - LXC
    - <https://www.hastexo.com/blogs/florian/2016/02/21/containers-just-because-everyone-else/>
  - Systemd-nspawn
    - <https://chimeracoder.github.io/docker-without-docker/#18>
    - <https://github.com/Fewbytes/rubber-docker>
    - <https://docs.google.com/presentation/d/10vFQfEUvpf7qYyksNqiy-bAxcy-bvF0OnUElCOtTTRc/edit#slide=id.g1012f66722_0_8>
  - runC

## Security Considerations 

- Image Authenticity
  - Use Private or Trusted Repositories
  - DockerHub Paid Plan has: scanning service
  - Use Docker Content Trust: <https://docs.docker.com/engine/security/trust/content_trust/>
    - use digital signatures for data sent to and received from remote Docker registries
    - image publishers can sign their images 
    - image consumers can ensure that the images they pull are signed
    - keys
      - an offline key that is the root of DCT for an image tag
      - repository or tagging keys that sign tags
      - server-managed keys such as the timestamp key, which provides freshness security guarantees for your repository
  - Docker Bench Security: <https://github.com/docker/docker-bench-security>
    - CIS Docker 1.13 Benchmark checks: <https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf>
- Excess Privileges
  - Do not run with `--privileged` (Don’t use privileged containers unless you treat them the same way you treat any other process running as root. <http://obrown.io/2016/02/15/privileged-containers.html>)
  - Drop Unnecessary Privileges and Capabilities <https://docs.docker.com/engine/security/security/>
    - <https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities>
- System Security - SeLinux AppArmor .... Check linux/defense section
- Limit Available Resource Consumption <https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources>
  ```
  -m / --memory: Set a memory limit
  --memory-reservation: Set a soft memory limit
  --kernel-memory: Set a kernel memory limit
  --cpus: Limit the number of CPUs
  --device-read-bps: Limit the read rate from a device
  ```
- Large Attack Surfaces
  - Implement an Audit Trail with Proper Logging  
    - When an application was deployed
    - Who deployed it
    - Why it was deployed
    - What its intent is
    - When it should be deprecated
  - Implement alerting

## Tips 

- Move dynamic steps to down to max utilization of cache

## Security References

- Docker vs. containerd vs. Nabla vs. Kata vs. Firecracker: <https://www.inovex.de/blog/containers-docker-containerd-nabla-kata-firecracker/>
- Docker Production Best Practices from Bret Fisher at DockerCon: <https://www.youtube.com/watch?v=V4f_sHTzvCI>
- Docker Security Best Practices: <https://blog.sqreen.com/docker-security/>
- 29 Docker security tools compared: <https://sysdig.com/blog/20-docker-security-tools/>
- Docker Security Cheat Sheet: <https://security.stackrox.com/rs/219-UEH-533/images/Docker-security-cheatsheet_final.pdf>
- Docker security: <https://docs.docker.com/engine/security/security/>
- BretFisher: What security concerns should I have with Docker? How should I go about locking it down? <https://github.com/BretFisher/ama/issues/17>
- Shifting Docker security left: <https://snyk.io/blog/shifting-docker-security-left/>
- At DockerCon: "Building a Docker Image Packaging Pipeline Using GitHub Actions": https://docker.events.cube365.net/docker/dockercon/content/Videos/SPWM3BdnCZWPN4fN9
- At DockerCon: "Your Container Has Vulnerabilities. Now What?" https://docker.events.cube365.net/docker/dockercon/content/Videos/GZpzJAapdrSXohzNz
