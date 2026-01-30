# 🏗️ System Design & Scalability Notes

This document tracks my journey through System Design principles and how I apply them to this **NestJS + React** architecture.

---

## 🟢 Module 1: Introduction to System Design
In this video, I learned that System Design is not just about writing code; it's about orchestrating components (APIs, Databases, Proxies) to satisfy requirements like **Scalability**, **Availability**, and **Reliability**.

* **Core Goal:** Building systems that handle millions of users concurrently despite hardware failures.
* **Key Insight:** Every design choice is a trade-off. For example, moving from a single server to multiple servers improves availability but increases network complexity.

---

## 🟢 Module 2: Horizontal vs. Vertical Scaling
This video explains the two primary ways to handle increased load on an application.

### 1. Vertical Scaling (Scaling Up)
* **Definition:** Adding more resources (CPU, RAM, SSD) to your existing server.
* **Analogy:** Upgrading a single-story house to a skyscraper.
* **Pros:** Simple implementation; zero changes needed to code; fast Inter-Process Communication (IPC).
* **Cons:** Hard hardware limit (you can't add infinite RAM); **Single Point of Failure (SPOF)**—if the one big server crashes, the whole app is down.

### 2. Horizontal Scaling (Scaling Out)
* **Definition:** Adding more server instances (machines) to the resource pool.
* **Analogy:** Building multiple houses in a colony instead of one giant building.
* **Pros:** High Availability (if one fails, others handle traffic); virtually infinite scaling.
* **Cons:** Requires a **Load Balancer**; introduces network latency (RPC is slower than IPC); requires **Statelessness**.

---

### 3. Key Concept: Stateless Architecture
For Horizontal Scaling to work in my **NestJS** backend, the services must be **Stateless**.

* **Detailed Meaning:** The server does not store "State" (like user session data) in its own local memory (RAM).
* **Why?** If Server 1 stores your login session in its RAM, and the Load Balancer sends your next request to Server 2, Server 2 won't know who you are.
* **My Implementation:** I use **JWT (JSON Web Tokens)**. The state lives in the token (on the client side) or a shared data store (like Redis), allowing any NestJS instance to process any request.

---

### 4. Visualizing the Scaling Flow (Mermaid)
```mermaid
graph TD
    User((User/Client)) --> LB[Load Balancer]
    subgraph "App Layer (Stateless & Horizontal)"
        LB --> Nest1[NestJS Instance 1]
        LB --> Nest2[NestJS Instance 2]
        LB --> Nest3[NestJS Instance 3]
    end
    subgraph "Data Layer"
        Nest1 --> DB[(Shared MySQL Database)]
        Nest2 --> DB
        Nest3 --> DB
    end
    
    style LB fill:#f96,stroke:#333,stroke-width:2px
    style DB fill:#69f,stroke:#333,stroke-width:2px