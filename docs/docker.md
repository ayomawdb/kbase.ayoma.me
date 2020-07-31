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

## Tips 

- Move dynamic steps to down to max utilization of cache