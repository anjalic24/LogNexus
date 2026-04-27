<p align="center">
  <img src="https://img.shields.io/badge/Java-21-orange?style=for-the-badge&logo=openjdk" />
  <img src="https://img.shields.io/badge/Spring_Boot-3.x-6DB33F?style=for-the-badge&logo=springboot" />
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react" />
  <img src="https://img.shields.io/badge/Kafka-3_Broker_Cluster-231F20?style=for-the-badge&logo=apachekafka" />
  <img src="https://img.shields.io/badge/Neo4j-5.15-4581C3?style=for-the-badge&logo=neo4j" />
  <img src="https://img.shields.io/badge/Redis-7.2-DC382D?style=for-the-badge&logo=redis" />
</p>

# LogNexus

**Enterprise Security Event Correlation Platform**

LogNexus is a microservice-based SIEM platform that ingests raw security log files from multiple sources, normalises and streams events through a 3-broker Kafka cluster, correlates them into a directed event graph (DEG) stored in Neo4j, enriches them with live threat intelligence, and surfaces the results through an interactive React dashboard featuring attack session clustering, kill-chain mapping, threat graph visualisation, and automated Root Cause Analysis (RCA) reports.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Repository Structure](#repository-structure)
3. [Prerequisites](#prerequisites)
4. [Quick Start](#quick-start)
   - [Step 1 — Infrastructure (Docker)](#step-1--start-the-infrastructure)
   - [Step 2 — Ingestion Service](#step-2--start-the-ingestion-service)
   - [Step 3 — Correlation Service](#step-3--start-the-correlation-service)
   - [Step 4 — LogNexus UI](#step-4--start-the-lognexus-ui)
5. [Supported Log Formats](#supported-log-formats)
6. [Kafka Topics](#kafka-topics)
7. [API Reference](#api-reference)
8. [UI Pages](#ui-pages)
9. [Port Reference](#port-reference)
10. [Environment Variables](#environment-variables)
11. [Health Checks](#health-checks)
12. [Stopping the Platform](#stopping-the-platform)

---

## Architecture

```
                            ┌──────────────────┐
                            │   Log Files      │
                            │  (.json / .log)  │
                            └────────┬─────────┘
                                     │ POST /logs/upload
                                     ▼
                ┌────────────────────────────────────────────┐
                │         IngestionService  (port 8081)      │
                │  Strategy-based parsers  ·  SSE live feed  │
                └────────┬──────────────────────┬────────────┘
                         │ normalized-events    │ bundle-signals
                         │ (12 partitions)      │ (3 partitions)
                         ▼                      ▼
              ┌──────────────────────────────────────────┐
              │        Apache Kafka  (3-Broker Cluster)  │
              │     kafka1:9092 · kafka2:9093 · kafka3:9094   │
              └──────────┬──────────────────────┬────────┘
                         │                      │
                         ▼                      ▼
                ┌──────────────────────────────────────────┐
                │     correlation-service  (port 8084)      │
                │  Event Consumer (12 threads)               │
                │  Redis Bundle Buffer  ·  Noise Gate        │
                │  Threat Enrichment (GeoIP, CISA KEV)       │
                │  Graph Builder  ·  Edge Scorer              │
                │  Kill Chain Mapper  ·  Attack Story Engine  │
                │  Resilience4j Circuit Breaker               │
                └─────┬────────────────────┬─────────────────┘
                      │                    │
               ┌──────┴──────┐      ┌──────┴──────┐
               │   Neo4j     │      │    Redis    │
               │  (Graph DB) │      │  (Buffer +  │
               │  port 7687  │      │   Cache)    │
               └─────────────┘      └─────────────┘
                      │
                      │  REST API  /api/correlation/*
                      ▼
              ┌────────────────────────────────────────┐
              │        LogNexus-ui  (port 5173)         │
              │  React 19  ·  Vite  ·  Recharts         │
              │  Dark / Light Theme  ·  SSE Live Feed    │
              └─────────────────────────────────────────┘
```

---

## Repository Structure

```
LogNexus/
├── IngestionService/            ← Spring Boot 3.5 — log parsing & Kafka producer
│   ├── src/main/java/com/vulnuris/IngestionService/
│   │   ├── controller/          ← IngestionController  (REST + SSE)
│   │   ├── parser/              ← Strategy-based log parsers (7 formats)
│   │   ├── kafka/               ← KafkaProducerService
│   │   ├── service/             ← IngestionService, LogStreamService, BundleControlService
│   │   ├── config/              ← KafkaProducerConfig, KafkaTopicConfig
│   │   ├── context/             ← IngestionContext
│   │   └── model/               ← CesEvent DTO
│   ├── pom.xml                  ← Java 21, Spring Boot 3.5.11
│   └── mvnw / mvnw.cmd
│
├── correlation-service/         ← Spring Boot 3.3 — correlation engine & REST API
│   ├── src/main/java/com/vulnuris/correlation/
│   │   ├── controller/          ← CorrelationController  (all REST endpoints)
│   │   ├── consumer/            ← EventConsumer  (Kafka listener, 12 threads)
│   │   ├── service/             ← GraphBuilderService, AttackStoryService,
│   │   │                           ThreatEnrichmentService, KillChainMapper,
│   │   │                           NoiseGateService, EdgeScorer, FeatureExtractor,
│   │   │                           AnomalyDetector, ImpossibleTravelDetector
│   │   ├── ingestion/           ← IngestionContext (strategy pattern)
│   │   ├── config/              ← KafkaConsumerConfig, KafkaTopicConfig
│   │   ├── model/               ← EventNode (Neo4j entity)
│   │   ├── repository/          ← EventRepository (Spring Data Neo4j)
│   │   ├── dto/                 ← CesEventDto, FilteredIngestRequest
│   │   └── utils/
│   ├── pom.xml                  ← Java 21, Spring Boot 3.3.4
│   └── mvnw / mvnw.cmd
│
├── LogNexus-infra/              ← Docker Compose infrastructure
│   └── docker-compose.yml       ← Zookeeper, Kafka ×3, Redis, Neo4j
│
├── LogNexus-ui/                 ← React 19 + Vite 5 frontend
│   ├── src/
│   │   ├── pages/               ← Dashboard, Ingest, BundleManager, LogExplorer,
│   │   │                           Sessions, TimelineView, GraphExplorer, RcaReport
│   │   ├── api/                 ← correlationApi.js (Axios client)
│   │   ├── contexts/            ← ActiveBundleContext, ThemeContext
│   │   ├── App.jsx              ← Router + sidebar navigation
│   │   ├── main.jsx             ← Entry point
│   │   └── index.css            ← Design system (dark + light tokens)
│   ├── package.json             ← React 19, Recharts, Lucide, Axios
│   └── vite.config.js           ← Dev proxy: /api → localhost:8084
```

---

## Prerequisites

| Tool | Required Version | Notes |
|------|-----------------|-------|
| **Docker Desktop** | ≥ 24.x | Must be running. Includes Docker Compose v2. Allocate **≥ 10 GB RAM** for the full stack. |
| **JDK** | **21** | Both services require Java 21. |
| **Maven** | 3.9+ | _Optional_ — the Maven wrapper (`mvnw` / `mvnw.cmd`) is included in each service. |
| **Node.js** | ≥ 18 LTS | Required for the React UI. |
| **npm** | ≥ 9 | Bundled with Node.js. |

> **Windows users:** PowerShell or Windows Terminal recommended. The Maven wrappers (`mvnw.cmd`) work natively.

---

## Quick Start

### Step 1 — Start the Infrastructure

All backing services run in Docker: Zookeeper, 3 Kafka brokers, Redis 7.2, and Neo4j 5.15.

```bash
cd LogNexus-infra

# Pull images and start everything (first run downloads ~2 GB)
docker compose up -d

# Watch until all 6 containers are healthy (takes 60–90 seconds)
docker compose ps
```

**Expected state:**

| Container | Port(s) | Status |
|-----------|---------|--------|
| `lognexus-zookeeper` | 2181 | healthy |
| `lognexus-kafka1` | 9092 | healthy |
| `lognexus-kafka2` | 9093 | healthy |
| `lognexus-kafka3` | 9094 | healthy |
| `lognexus-redis` | 6379 | healthy |
| `lognexus-neo4j` | 7474, 7687 | healthy |

> **Neo4j** takes 60–90s on first boot. Wait for `healthy` before starting the Correlation Service.

**Neo4j Browser (optional):** [http://localhost:7474](http://localhost:7474) — login with `neo4j` / `password123`.

---

### Step 2 — Start the Ingestion Service

```bash
cd IngestionService

# Windows (PowerShell)
.\mvnw.cmd spring-boot:run

# macOS / Linux / Git Bash
./mvnw spring-boot:run
```

> First run downloads Maven dependencies (~2–3 min). Subsequent starts are instant.

**Verify:**
```bash
curl http://localhost:8081/actuator/health
# → {"status":"UP"}
```

---

### Step 3 — Start the Correlation Service

Open a **new terminal** (keep the Ingestion Service running):

```bash
cd correlation-service

# Windows (PowerShell)
.\mvnw.cmd spring-boot:run

# macOS / Linux / Git Bash
./mvnw spring-boot:run
```

**Verify:**
```bash
curl http://localhost:8084/actuator/health
# → {"status":"UP","components":{"kafka":...,"neo4j":...,"redis":...}}
```

> **Custom Neo4j password:** If you changed the Neo4j password from the default `password123`, set the environment variable before starting:
> ```powershell
> # PowerShell
> $env:NEO4J_PASSWORD = "your_new_password"
> .\mvnw.cmd spring-boot:run
> ```
> ```bash
> # Bash
> NEO4J_PASSWORD=your_new_password ./mvnw spring-boot:run
> ```

---

### Step 4 — Start the LogNexus UI

Open a **new terminal**:

```bash
cd LogNexus-ui

# Install dependencies (first time only)
npm install

# Start the development server
npm run dev
```

Open **[http://localhost:5173](http://localhost:5173)** in your browser.

> The Vite dev server proxies all `/api/*` requests to `http://127.0.0.1:8084` (the Correlation Service), so no CORS configuration is needed during development.

---

## Supported Log Formats

The Ingestion Service auto-detects and parses the following log formats via the Strategy Pattern:

| Parser | Source | File Format |
|--------|--------|-------------|
| `WindowsSecurityParser` | Windows Event Log | JSON |
| `SyslogParser` | Linux / BSD syslog | `.log` (text) |
| `PaloAltoFirewallParser` | Palo Alto NGFW | JSON |
| `CloudTrailParser` | AWS CloudTrail | JSON |
| `O365Parser` | Microsoft 365 Audit | JSON |
| `WazuhAlertsParser` | Wazuh SIEM Alerts | JSON |
| `WebAccessLogParser` | Apache / Nginx access logs | `.log` (text) |

---

## Kafka Topics

| Topic | Partitions | Replication Factor | Purpose |
|-------|-----------|-------------------|---------|
| `normalized-events` | 12 | 3 | High-throughput event stream from Ingestion → Correlation |
| `bundle-signals` | 3 | 3 | Low-throughput control plane — triggers bundle processing |

Both topics use 7-day time-based retention and `min.insync.replicas=2`.

---

## API Reference

### Ingestion Service — `http://localhost:8081`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/logs/upload` | Upload log files (multipart). Returns `bundleId`. Optional `excludeSources` param. |
| `GET` | `/logs/stream/{bundleId}` | SSE live stream of ingestion progress. |
| `POST` | `/logs/cancel/{bundleId}` | Cancel an in-progress ingestion. |

### Correlation Service — `http://localhost:8084`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/correlation/status` | Service health status. |
| `GET` | `/api/correlation/bundles` | List all processed bundles with event counts. |
| `GET` | `/api/correlation/bundles/{bundleId}/status` | Status of a specific bundle. |
| `GET` | `/api/correlation/events/{bundleId}?page=0&size=100` | Paginated events for a bundle. |
| `GET` | `/api/correlation/graph/{bundleId}` | Full graph data (nodes + edges) for visualisation. |
| `GET` | `/api/correlation/attack-sessions/{bundleId}` | Attack sessions with kill-chain stages. |
| `GET` | `/api/correlation/rca/{bundleId}` | Full RCA report (timeline, assets, causal chain). |
| `POST` | `/api/correlation/manual-ingest` | Manually ingest a JSON array of events. |
| `POST` | `/api/correlation/filtered-ingest` | Ingest with severity / time filters. |
| `DELETE` | `/api/correlation/bundles/{bundleId}` | Delete a specific bundle and its orphaned entities. |
| `DELETE` | `/api/correlation/bundles` | ⚠️ Purge all data from Neo4j. |

---

## UI Pages

| Route | Page | Description |
|-------|------|-------------|
| `/` | Dashboard | Overview stats and quick-access cards. |
| `/ingest` | Log Upload | Drag-and-drop file upload with SSE live progress. |
| `/bundles` | Bundle Manager | List, inspect, and delete processed bundles. |
| `/explorer` | Log Explorer | Data-lake query interface with severity/search filters. |
| `/sessions` | Attack Sessions | Clustered attack session cards with kill-chain display. |
| `/timeline` | Attack Timeline | Chronological event timeline visualisation. |
| `/graph` | Threat Graph | Interactive directed-event-graph visualisation (nodes + edges). |
| `/rca` | RCA Reports | Automated root cause analysis with export-to-PDF. |

---

## Port Reference

| Service | Port | Protocol |
|---------|------|----------|
| **LogNexus UI** (Vite dev) | `5173` | HTTP |
| **IngestionService** | `8081` | HTTP |
| **correlation-service** | `8084` | HTTP |
| Zookeeper | `2181` | TCP |
| Kafka Broker 1 | `9092` | TCP |
| Kafka Broker 2 | `9093` | TCP |
| Kafka Broker 3 | `9094` | TCP |
| Redis | `6379` | TCP |
| Neo4j Browser (HTTP) | `7474` | HTTP |
| Neo4j Bolt | `7687` | TCP |

---

## Environment Variables

| Variable | Service | Default | Description |
|----------|---------|---------|-------------|
| `NEO4J_PASSWORD` | correlation-service | `password123` | Neo4j database password. Must match the `NEO4J_AUTH` value in `docker-compose.yml`. |

---

## Health Checks

```bash
# ── Infrastructure ──────────────────────────────────────────────
docker compose -f LogNexus-infra/docker-compose.yml ps

# Redis
docker exec lognexus-redis redis-cli ping
# → PONG

# Neo4j
docker exec lognexus-neo4j cypher-shell -u neo4j -p password123 "RETURN 1"

# Kafka — list topics
docker exec lognexus-kafka1 kafka-topics --bootstrap-server localhost:9092 --list

# ── Services ────────────────────────────────────────────────────
curl http://localhost:8081/actuator/health        # Ingestion
curl http://localhost:8084/actuator/health        # Correlation

# ── Functional ──────────────────────────────────────────────────
curl http://localhost:8084/api/correlation/status
curl http://localhost:8084/api/correlation/bundles
```

---

## Stopping the Platform

```bash
# 1. Stop the UI — Ctrl+C in the npm terminal

# 2. Stop the Java services — Ctrl+C in each mvnw terminal

# 3. Stop Docker containers (data is preserved in named volumes)
cd LogNexus-infra
docker compose down

# 4. To also delete ALL stored data (Neo4j graph, Kafka logs, Redis state):
docker compose down -v
```

---

<p align="center">
  <strong>Vulnuris Security Solutions</strong><br/>
  Built with Spring Boot · Apache Kafka · Neo4j · Redis · React
</p>
