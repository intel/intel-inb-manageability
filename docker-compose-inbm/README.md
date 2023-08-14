This is a docker-compose directory that can launch INBM in containers.

Containers:
- certgen generates mqtt certs for each service, inbc, and the mqtt broker
- configuration runs the INBM configuration agent
- dispatcher runs the INBM dispatcher agent
- inbc runs a container that stays open so inbc can be 'docker exec'ed inside it
- mosquitto runs the mqtt broker
- telemetry runs the INBM telemetry agent

Prerequisites:
- Install docker and docker-compose
- Set proxy variables for your system.
- Set up docker to use proxy correctly. Test with docker pull hello-world && docker run hello-world.
- Copy Intel-Manageability.preview.tar.gz from an INBM native build into this directory.
- Run docker-compose build to build the docker containers.
- Run docker-compose up -d to bring up the INBM docker-compose stack in the background (daemon mode).
