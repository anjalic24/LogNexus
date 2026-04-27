# LogNexus Infrastructure

This directory contains the core infrastructure required to run the LogNexus platform. All data-layer services are fully containerized and orchestrated via Docker Compose.

##  Getting Started

To spin up the entire infrastructure environment, run:

```bash
docker-compose up -d
```

To view the live logs of the running services:

```bash
docker-compose logs -f
```

To stop and completely remove the environment (including all data volumes):

```bash
docker-compose down -v
```

---

##  Services Overview

| Service | Version | Port(s) | Description |
|---|---|---|---|
| **Zookeeper** | 7.4.4 | `2181` | Coordinates the Kafka cluster and manages broker metadata. |
| **Kafka Broker 1** | 7.4.4 | `9092` | Primary event streaming broker. |
| **Kafka Broker 2** | 7.4.4 | `9093` | Secondary broker for partitioning and replication. |
| **Kafka Broker 3** | 7.4.4 | `9094` | Tertiary broker for high-availability. |
| **Redis** | 7.2 | `6379` | High-speed caching layer for correlation states. |
| **Neo4j** | 5.15.0 | `7687` (Bolt), `7474` (HTTP) | Native graph database storing the Directed Event Graph (DEG). |
| **Kafdrop** | Latest | `9000` | Web UI for monitoring Kafka topics and browsing messages. |

---

## Credentials & Environment Variables

The default credentials for the local development environment are:

- **Neo4j Username**: `neo4j`
- **Neo4j Password**: `password123` (Set via `NEO4J_AUTH`)

*Note: In a production environment, ensure all default credentials and plaintext environment variables are securely managed via a vault or Docker secrets.*

---

##  Core Kafka Topics

The infrastructure automatically provisions the following core topics upon startup:

- `normalized-events` (12 partitions, replication factor 3)
- `bundle-signals` (3 partitions, replication factor 3)

You can monitor these topics via the Kafdrop Web UI at [http://localhost:9000](http://localhost:9000).
