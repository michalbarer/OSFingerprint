# OSFP Demo: Setup and Instructions

This document provides step-by-step instructions to set up and run the OSFP (Operating System Fingerprint) demo using Docker and Docker Compose.

---

## Prerequisites

Make sure the following tools are installed:
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

---

## Setup Instructions

### 1. Create a Custom Docker Network
To allow containers to communicate with each other, create a custom Docker network:
```bash
docker network create --driver bridge --subnet=192.168.1.0/24 custom_network
```
Verify the network:
```bash
docker network inspect custom_network
```

### 2. Build and Start the Containers
Use Docker Compose to build and run the containers:
```bash
docker-compose down
docker-compose up --build -d
```

### 3. Access the OSFP Container
Log into the `OSFP` container to run demo commands:
```bash
docker exec -it demo-osfp-1 bash
```

### 4. Run OSFP Command
Inside the `OSFP` container, execute the following command:
```bash
osfp -h 192.168.1.102 -op 80
```
* `-h`: Specifies the target host. In this case, it is the Linux (Ubuntu) container (192.168.1.102).
* `-op`: Specifies the port to fingerprint the target operating system. Here, port 80 is used.

---
## Expected Output
The `osfp` command will attempt to fingerprint the operating system of the target container (`192.168.1.102`) using the specified port.

The output will display the detected operating system along with a confidence score. Here is an example of the output:
```
+-------------------------------------------------+---------+
| os                                              |   score |
+=================================================+=========+
| Linux 4.15                                      |  86.32  |
+-------------------------------------------------+---------+
| Linux 6.0                                       |  85.955 |
+-------------------------------------------------+---------+
| Android 10                                      |  85.5   |
+-------------------------------------------------+---------+
| Linux 2.6.32                                    |  84.89  |
+-------------------------------------------------+---------+
| Linux 3.4 - 3.10                                |  84.86  |
+-------------------------------------------------+---------+
| Synology DiskStation Manager 5.2-5644           |  84.495 |
+-------------------------------------------------+---------+
| Linux 4.19                                      |  84.495 |
+-------------------------------------------------+---------+
| Linux 5.0 - 5.14                                |  83.875 |
+-------------------------------------------------+---------+
| Ubiquiti Dream Machine Pro gateway (Linux 4.19) |  83.7   |
+-------------------------------------------------+---------+
| Ubiquiti AirOS 5.6.2 (Linux 2.6.32)             |  83.7   |
+-------------------------------------------------+---------+
```
---

## Troubleshooting
1. **Container Not Running**: If a container exits unexpectedly, inspect its logs:
```bash
docker ps -a
docker logs <container_id>
```

2. **Network Issues**: If containers cannot communicate, verify they are attached to `custom_network`:
```bash
docker network inspect custom_network
```

3. **Rebuilding Containers**: If changes are made to the `Dockerfile` or `docker-compose.yml`, rebuild the containers:
```bash
docker-compose up --build -d
```
