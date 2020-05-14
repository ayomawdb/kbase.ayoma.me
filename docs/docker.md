# Docker 

## VNotes

- Why based on: The works-on-my-machine problem (env-variable missing, server not configured correctly, jdk version, db)
- Container: Fully self contained environment (servers + apps + configuration + env variables, ...)
- Image: Definition of container (environment). Unit of deployment. Can be run multiple times.
- Explain ability to have different OS-es inside containers. 
  - Sharing of Kernel.
- Originally based on LXC feature of Kernel. 
- Installation.
  - Enable VT-X / AMD-V in Bios
  - Requirement of having installed on dev-machines
  - Docker outside of linux using VM
- Deploying a web application (pre-built)
  - `docker image pull <image>`
- Show Dockerfile and walk through 
  - EXPOSE 
  - Deploy to tomcat 
- Run `docker container run -p <ex-port>:<in-port> <image>`
  - Mac/Windows have to use the Ip address instead of `localhost`.  `docker container ls`, `docker-machine ip`
- Stop `docker container stop <id>`