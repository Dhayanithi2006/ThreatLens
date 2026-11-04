# 🔐 ThreatLens GraphOps
### Graph-Based Cybersecurity Threat Hunting & Blast-Radius Analysis

**ThreatLens GraphOps** is a graph-based cybersecurity platform that helps security analysts investigate potential cyber threats, explore attack paths and identify systems that could be affected by an attack.

## 🚨 Problem

Security data is scattered across endpoints, networks, servers and applications. This makes it difficult for SOC teams to connect alerts, trace potential attack paths and understand the possible impact of a cyberattack.

## 💡 Our Solution

ThreatLens GraphOps connects security data into a unified **Neo4j Knowledge Graph**, using graph algorithms to visualize system relationships, investigate potential threats and assess security risks.

## ✨ Key Features

- **Security Data Ingestion:** Import and process structured security data.
- **Knowledge Graph Visualization:** Explore relationships between users, devices, servers and critical assets.
- **Attack Path Analysis:** Use Dijkstra's algorithm to identify potential routes to critical assets.
- **Blast-Radius Analysis:** Apply BFS to identify potentially affected systems within multiple hops.
- **Choke-Point Identification:** Use graph centrality to identify structurally important systems.
- **Threat Investigation:** Connect suspicious events and related security alerts.
- **Containment Simulation:** Evaluate proposed isolation scenarios without modifying the actual graph.

## ⚙️ Technology Stack

| Component | Technologies |
|---|---|
| Frontend | HTML, CSS, JavaScript |
| Graph Visualization | Cytoscape.js |
| Backend | Python, FastAPI |
| Database | Neo4j, Cypher |
| Algorithms | BFS, Dijkstra, DFS, Centrality |
| Machine Learning | Scikit-learn |
| Testing | Pytest |
| Tools | Git, GitHub, Docker |

## 🔄 How It Works

```text
Security Data
     ↓
Data Ingestion & Processing
     ↓
Neo4j Knowledge Graph
     ↓
Graph Analytics
     ↓
Attack Path & Blast-Radius Analysis
     ↓
Interactive Security Dashboard
     ↓
Evidence-Based Investigation
```

## 🎯 Impact

ThreatLens helps security analysts:

- Understand how systems are connected.
- Explore potential attacker movement.
- Identify potentially exposed critical assets.
- Prioritize important systems for investigation.
- Evaluate containment strategies before taking action.

## 🔮 Future Scope

- More live security data integrations.
- Advanced graph machine learning.
- Real-time Kafka-based event streaming.
- Enhanced threat intelligence and automated reporting.

## 👥 Project Information

**Project Name:** ThreatLens GraphOps  
**Domain:** Cybersecurity | Threat Hunting | Graph Analytics  
**Focus:** Proactive Threat Investigation and Attack-Path Analysis

---

**Connecting security events. Visualizing attack paths. Understanding cyber risks.**
