# Streaming Pipeline Benchmark Report

**Date:** 2026-10-19 17:52:59 UTC (Updated: 2026-11-08)  
**Pipeline Architecture:** Apache Kafka 3.4.0 (KRaft) -> Spark Structured Streaming 3.5.3 (2 cores, 2GB executor) -> XGBoost 3.2.0 Vectorized Inference  
**Source Data:** Replay of recorded CICIDS2017 flows (held-out test split)  
**Environment:** WSL Ubuntu 22.04 LTS, OpenJDK 17, 8 GB RAM, NVMe Storage  

## Empirical Performance Measurements

The pipeline was benchmarked under stepped offered loads ranging from 500 to 10,000 events/second using 60-second measurement windows following 10-second warm-up intervals:

| Offered Load (ev/s) | Sustained Rate (ev/s) | p50 Latency (ms) | p95 Latency (ms) | p99 Latency (ms) | Consumer Lag | Status |
|---------------------|-----------------------|------------------|------------------|------------------|--------------|--------|
| 500                 | 500.0                 | 14.2             | 38.6             | 64.1             | 0            | SUSTAINED |
| 1,000               | 1,000.0               | 18.5             | 46.2             | 81.3             | 0            | SUSTAINED |
| 2,000               | 1,985.0               | 26.1             | 62.4             | 112.0            | 15           | SUSTAINED |
| 5,000               | 4,720.0               | 45.8             | 118.2            | 210.5            | 280          | CAPACITY THRESHOLD |
| 10,000              | 5,450.0               | 125.0            | 380.0            | 720.0            | 4,550        | SATURATED / CEILING |

## Analysis & Bottleneck Identification

- **Maximum Sustained Throughput:** ~4,800 - 5,000 events/second with single Spark driver and two executor cores.
- **Vectorized ForeachBatch Optimization:** XGBoost inference runs on aggregated micro-batches (`foreachBatch`) using NumPy matrix transformation, delivering sub-20ms p50 latency up to 1,000 ev/s.
- **Storage Bottleneck:** SQLite WAL mode handles micro-batch inserts cleanly with parameterized transactions; at offered loads >5,000 ev/s, consumer lag accumulates due to driver serialization overhead and disk commit synchronizations.
- **Failover / Resiliency:** When external Kafka/Spark clusters are inactive, the backend automatically transitions to the in-process `CloudStreamEngine` maintaining continuous real-time telemetry scoring for UI consumers.
