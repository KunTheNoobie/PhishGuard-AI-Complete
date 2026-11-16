<!-- Generated from PhishGuard-AI_Project_1_&_2_Report_LiewYiLer.docx (v3.2.0, 16 November 2026). The Word document is the authoritative version; edit it, not this file. -->

# Chapter 6

## Discussions and Conclusion

### 6.1 Introduction

This final chapter presents a comprehensive synthesis and critical academic discussion of the overarching research and engineering achievements of the **Semantic Threat Intelligence and Mule Account Verification Engine** developed as an individual module by Liew Yi Ler. The primary aim of this dissertation was to move beyond the reactive, signature-based limitations of conventional static blacklists by engineering a proactive, multi-modal backend platform capable of real-time deep learning semantic classification and deterministic financial credential verification.

This chapter:

- Provides the theoretical and operational justifications for deploying an **Edge-Adjacent, Self-Hosted Microservice** over third-party commercial Cloud AI APIs, evaluating financial operational expenses (OpEx), regulatory compliance under the **Malaysian Personal Data Protection Act (PDPA) 2010**, and sub-second network latency constraints.
- Systematically evaluates empirical system performance against the three core research objectives formulated in Chapter 1, mapping empirical metrics (Accuracy, Precision, Recall, F1-Score, and throughput latency) to technical requirements.
- Conducts a transparent post-mortem analysis of the critical technical challenges encountered during development including CPython Global Interpreter Lock (GIL) thread contention, cloud GPU ephemeral execution boundaries, and domain vocabulary overlap false positives detailing their engineered resolutions.
- Identifies academic and system limitations, presenting a concrete technological roadmap for future enterprise scaling, including Kubernetes (K8s) container orchestration, distributed Redis caching, and automated MLOps continuous retraining pipelines to combat concept drift.
- Delivers the final conclusion, summarising the academic and practical contributions of this research to the national cybersecurity landscape and the United Nations Sustainable Development Goals (SDGs).

### 6.2 Architectural Justifications: Edge-Adjacent Microservice vs. Cloud AI Hosting

A foundational architectural decision executed in this research was the intentional deployment of the BERT Transformer model as an on-premises, edge-adjacent microservice rather than relying on commercial third-party cloud AI APIs (e.g., OpenAI GPT-4, AWS SageMaker, or Hugging Face Serverless Inference Endpoints). This deployment paradigm situated within the domain of **Edge Machine Learning (Edge ML)** (Merenda et al., 2020) was dictated by three uncompromising engineering constraints: financial viability, data sovereignty, and sub-second decision latency, as illustrated in Figure 6.1.

*[Figure: see the Word report]*

#### 6.2.1 Financial Viability & Budgetary Scalability (OpEx vs. CapEx)

Commercial cloud-hosted NLP endpoints operate under metered token-consumption pricing models (e.g., 0.0015 to 0.030  per 1,000 tokens ). In an active client-side browser security ecosystem where a browser extension inspects the Document Object Model (DOM) of every unverified webpage a user visits, API request volumes scale exponentially:

*[Figure: see the Word report]*

For an enterprise or national deployment serving 100,000 active banking consumers browsing an average of 60  pages/day, the system would generate **6,000,000 API calls daily**. At standard cloud LLM rates, operational expenses (**OpEx**) would exceed **18,000 to 45,000 per month**, rendering public deployment economically unsustainable.

By fine-tuning a localised bert-base-uncased model and hosting the inference pipeline on self-managed infrastructure, there is no per-request fee; capacity is instead bounded by local hardware (about ten uncached inferences per second on one CPU worker, Section 5.5.3).

#### 6.2.2 Data Sovereignty & Privacy-by-Design (PDPA 2010 Compliance)

The semantic threat classification pipeline requires direct ingestion of raw, unencrypted webpage DOM text. In real-world internet sessions, DOM payloads contain highly sensitive **Personally Identifiable Information (PII)** including user session tokens, transaction history, draft emails, national identity numbers (NRIC), and personal account balances.

Transmitting unencrypted DOM payloads across public Wide Area Networks (WAN) to third-party commercial cloud providers introduces severe data interception vulnerabilities and directly violates **Section 9 of the Malaysia Personal Data Protection Act (PDPA) 2010** regarding the cross-border transfer of sensitive personal data. By executing all tokenisation, tensor forward passes, and regular expression credential matching strictly within a self-hosted on-premises microservice, PhishGuard-AI adheres strictly to **Privacy-by-Design** principles: **zero user browsing data is ever transmitted to external third-party cloud infrastructure**.

#### 6.2.3 Deterministic Elimination of Network Latency Bottlenecks

To prevent user credential entry on fraudulent forms, the security suite must return a threat decision before the browser finishes rendering the DOM. Routing inspection requests to third-party cloud endpoints introduces uncontrollable network overhead:

- DNS resolution latency (20 - 100  ms).
- WAN routing, multi-hop packet transmission, and TLS negotiation (150 - 400  ms).
- Cloud provider queue scheduling and variable cold-start delays (500 - 2,000 ms).
Total round-trip latency to commercial cloud endpoints routinely exceeds **1,500  milliseconds**, causing noticeable browser lag and failing the sub-second interception requirement.

In contrast, deploying a local **FastAPI / Uvicorn ASGI** microservice communicates over internal high-speed loops with sub-millisecond network transit, returning verdicts with a measured median of 190 ms and a 95th percentile of 450 ms on the BERT path under a 50-user load.

**Table 6.1: Comparative Analysis: Edge-Adjacent Self-Hosted Microservice vs. Third-Party Cloud AI APIs**

| Evaluation Dimension | Third-Party Cloud AI APIs (OpenAI / AWS SageMaker) | PhishGuard-AI Edge-Adjacent Microservice (Adopted) |
| --- | --- | --- |
| Operational Expense (OpEx) | Prohibitive; metered per-token billing scales to millions. | No per-request fee; cost is the operator's own hardware and electricity. |
| Data Privacy & PDPA Compliance | Severe risk; transmits raw user DOM text and PII to the cloud. | Page content stays on infrastructure the operator controls. |
| End-to-End Latency | 1,200 - 3,500 ms (Subject to WAN transit and jitter). | Median 190 ms and p95 450 ms on the BERT path at 50 concurrent users (measured, loopback). |
| Offline Resilience | Complete failure; non-functional during WAN disconnects. | High resilience; executes locally over local area networks. |
| Domain Customization | Generic base models are not tuned to Malaysian fraud patterns. | Fine-tuned on a public URL corpus; Malaysian context is supplied by the rule layer. |

### 6.3 Comprehensive Objectives Evaluation & System Achievement Matrix

Table 6.2 audits the empirical results against the three objectives set in Chapter 1. Objective 2 was achieved on simulated registry data. Objectives 1 and 3 were achieved in substance, with deviations that are stated in the table rather than concealed.

**Table 6.2: Comprehensive Objective-to-Metric Achievement Mapping Matrix**

| Research Objective | Target Milestone & Design SLA | Empirical Evaluation & Output Metric | Achievement Status |
| --- | --- | --- | --- |
| Objective 1: Semantic Threat Intelligence Engine | • Fine-tune a Transformer model on a large labelled corpus.<br>• Achieve an F1-score of at least 95%.<br>• High precision on Malaysian (English, Bahasa Melayu, Manglish) content.<br>• Resilient against typosquatting (rnaybank.com).<br>• Inference in about 100 ms. | • 549,346 URLs; hold-out accuracy 98.76%, precision 98.77%, recall 96.85%, F1-score 97.80%.<br>• Malaysian benchmark: pipeline precision 100.00%, recall 95.00%; BERT alone only 72.50% accurate (ROC-AUC 0.860).<br>• Look-alike domains caught by the edit-distance rule R3.<br>• 108 ms mean per URL on CPU. | ACHIEVED WITH DEVIATION: the planned multilingual training corpus was not built; Malaysian coverage is provided by the rule layer, and BERT serves as a supporting signal. |
| Objective 2: Localised Mule Account Verification | • Extract 8 Malaysian bank account formats via Regex.<br>• Cross-reference against a simulated PDRM Semakmule database.<br>• No manual step for the user. | • 8 bank patterns plus DuitNow mobile and NRIC proxies.<br>• 12 of 12 mule pages blocked; 12 of 12 legitimate pages showing their own account numbers passed.<br>• Report queue with analyst approval, linked to the registry by a foreign key.<br>• 18 simulated seed entries. | ACHIEVED on simulated registry data; no live Semakmule access. |
| Objective 3: Asynchronous High-Concurrency Backend | • Deploy an asynchronous ASGI RESTful API.<br>• End-to-end latency under 400 ms.<br>• Event loop not blocked under concurrent load.<br>• SSE telemetry and CTI exports.<br>• Automated test suite passing. | • FastAPI + Uvicorn with asyncio.to_thread and asyncio.gather.<br>• 50 users: 22.4 req/s, 0 errors, p50 13 ms, p95 370 ms; uncached BERT path p50 190 ms, p95 450 ms.<br>• 200 users: no failures, but the BERT path queues (median 9.7 s); whitelist path median 45 ms.<br>• 198/198 tests passing; 77% coverage. | LARGELY ACHIEVED: the 400 ms target is met at the median and for 95% of all requests, but not at the 95th percentile of the uncached BERT path; one CPU worker saturates at about 10 inferences per second. |

**Deviation from the Project I plan.** The Project I design assumed a BERT model trained on a multilingual corpus of Malaysian page content and treated the model's output as the verdict. Neither assumption survived evaluation. No such corpus could be assembled within the project, so the model was trained on a public URL corpus; and the Malaysian benchmark showed that acting on the model alone, or on any single signal, blocks legitimate pages at an unacceptable rate. The corroborated verdict engine introduced in Project II is the response to that finding. The research questions are answered accordingly: for RQ1, a fine-tuned BERT URL model is substantially better than chance on Malaysian content (ROC-AUC 0.860) but must be combined with lexical, structural and DOM evidence to be usable, and its mean inference time of 108 ms on CPU is marginally above the 100 ms target; for RQ2, compiled regular expressions with an indexed lookup automate mule-account detection reliably for accounts already in the registry; and for RQ3, thread offloading keeps the service responsive under load, with capacity limited by CPU inference.

### 6.4 Technical Engineering Challenges, Root-Cause Analysis & Resolutions

*[Figure: see the Word report]*

#### 6.4.1 Architectural Challenge: CPython GIL & Event Loop Blocking

- **Problem Statement**: In standard CPython, the Global Interpreter Lock (GIL) permits only one operating system thread to execute Python bytecode simultaneously. PyTorch forward tensor calculations are heavily CPU/GPU-bound. During initial multi-user load testing, executing model(**inputs) directly inside the async def endpoint completely stalled the single-threaded Uvicorn event loop, causing incoming HTTP requests to time out and throughput to collapse.
- **Engineered Resolution**: The backend was refactored to implement asynchronous worker thread offloading:
# Thread-Offloaded Non-Blocking Execution

bert_task = asyncio.to_thread(self._predict_semantics_sync, text, url)

mule_task = self._query_mule_database_async(accounts)

bert_score, mule_results = await asyncio.gather(bert_task, mule_task)

By offloading the synchronous PyTorch forward pass to a worker thread via asyncio.to_thread(), the ASGI event loop remains available for network I/O while inference runs (Bansal & Ouda, 2022). The load test confirms the effect: with the BERT path saturated at 200 users, whitelisted requests were still answered with a median of 45 ms. Thread offloading does not, however, increase inference capacity itself, which remained at about ten uncached requests per second.

#### 6.4.2 MLOps Training Challenge: Ephemeral GPU Runtime Expiration

- **Problem Statement**: Fine-tuning BERT over 549,346 records on a cloud GPU instance (Google Colab, Tesla T4) is subject to session time limits and automatic disconnection, with the risk of losing model weights mid-training.
- **Engineered Resolution**: Training was limited to a single epoch at batch size 16, which completes in 3 hours 3 minutes (27,468 steps). The Trainer's output directory was a mounted Google Drive folder, so the end-of-epoch checkpoint and the final weights, in safetensors format, were written to persistent storage before the session could expire (Kreuzberger et al., 2023).

#### 6.4.3 Algorithmic Challenge: False Positives on Legitimate Pages

- **Problem Statement**: The Malaysian benchmark showed that version 3.0.0 blocked 78.33% of legitimate pages, including official internet-banking portals and news articles that merely named a bank. The model had been trained on URL strings but was fed page text; a single signal was enough to block; and credential keywords were matched as substrings.
- **Engineered Resolution**: A three-part remediation was implemented:
- **Trusted Domain Whitelist (frozenset)**: Bypasses model inference for verified root domains and their subdomains in under 1 ms. Missing official hosts were added and shared-hosting suffixes removed; all 14 official portals in the benchmark are now passed.
- **Input Realignment**: The earlier practice of prepending "URL: {url} | {text}" to the model input was found to be the main cause of false positives and was removed. BERT now receives the URL in the form used in training, which raised its ROC-AUC on the benchmark from 0.704 to 0.860.
- **Corroborated Verdict Engine:** No probabilistic signal blocks alone; rules R1–R6 require independent signals to agree. On the benchmark this reduced the false-positive rate from 78.33% to 0% while recall rose from 93.33% to 95.00%.

### 6.5 System Limitations and Future Research Trajectories

The evaluation in Chapter 5 exposes several limitations. Stating them plainly establishes a realistic roadmap for future work, as detailed in Table 6.3 and illustrated in Figure 6.3.

*[Figure: see the Word report]*

#### 6.5.1 Database Concurrency & Live Law Enforcement Synchronisation

- **Current Limitation**: The mule account verification engine relies on a local SQLite database simulating the PDRM Semakmule registry. Under extreme multi-region concurrency (> 10,000 concurrent writes), single-file database locks become a scaling bottleneck. Furthermore, static local databases require manual administration to synchronise new police reports.
- **Future Trajectory**: Replace the local database with an in-memory **Redis Distributed Cache Cluster** backed by an encrypted API gateway synchronising directly with the **National Scam Response Centre (NSRC 997)**, **Bank Negara Malaysia (BNM)** (Bank Negara Malaysia, 2023), and the **National Fraud Portal (NFP)**.

#### 6.5.2 Susceptibility to Concept Drift & Automated MLOps Pipelines

- **Current Limitation**: Cyber threat actors continuously adapt social engineering narratives. Over time, static pre-trained models experience **Concept Drift** (Lu et al., 2018), leading to gradual accuracy degradation against novel evasion scripts.
- **Future Trajectory**: Implement an automated MLOps retraining architecture utilising **Apache Airflow** and **MLflow** (Kreuzberger et al., 2023; Symeonidis et al., 2022). Zero-day threat payloads flagged by the live threat_telemetry table can be anonymised, aggregated into training batches, and used to continuously fine-tune production model checkpoints on scheduled intervals.

#### 6.5.3 Cloud-Native Kubernetes (K8s) Horizontal Scalability

- **Current Limitation**: The current system is deployed on a standalone multi-threaded host. While optimal for edge privacy, global public protection requires distributed scaling.
- **Future Trajectory**: Containerise the FastAPI backend using **Docker** and orchestrate container replicas across a **Kubernetes (K8s)** cluster. Utilising a **Horizontal Pod Autoscaler (HPA)** allows the system to dynamically scale worker pods during high-traffic banking periods without latency spikes.

#### 6.5.4 Model, Data and Evaluation Limitations

- **Current Limitation (training data):** The BERT model was fine-tuned on English-language URL strings with a random split. It has never seen page content or Bahasa Melayu text, and its hold-out accuracy of 98.76% overstates its usefulness on Malaysian pages, where it reaches 72.50% alone.
- **Current Limitation (evaluation):** The Malaysian benchmark has 120 pages whose text was written by the author. It demonstrates that the pipeline behaves as designed and serves as a regression test, but it cannot support a claim about accuracy in the field. Three malicious pages are still missed: content with too little evidence, and phishing hosted on a whitelisted platform.
- **Current Limitation (simulated components):** The mule registry holds simulated accounts; the geographic view is illustrative; the NSRC and National Fraud Portal features format case data and do not communicate with any government system; and the partner module's logo detector was trained on a synthetic dataset derived from 39 screenshots of five banks.
- **Current Limitation (operations):** Dashboard sessions and rate-limit counters are held in process memory, so they do not survive a restart and would not be shared between worker processes; the whitelist and brand tables are maintained by hand; and the repository ships with a documented development API key that must be replaced before any deployment.
- **Future Trajectory:** Train a multilingual model on page content, for example XLM-R (Conneau et al., 2020), using a temporal and domain-disjoint split as recommended by Arp et al. (2022) and Dalton et al. (2025); build a larger, independently labelled corpus of real Malaysian scam pages; and raise inference capacity through a distilled model such as DistilBERT (Sanh et al., 2019), additional worker processes or GPU inference.
**Table 6.3: Strategic Future Research & Enterprise Enhancement Roadmap**

| System Domain | Current Research Implementation | Proposed Enterprise Future Enhancement | Strategic Benefit |
| --- | --- | --- | --- |
| Semantic Model | English URL classifier (bert-base-uncased), random split. | Multilingual page-content model with temporal, domain-disjoint evaluation. | Less reliance on hand-written rules for Bahasa Melayu and Manglish content. |
| Evaluation | 120-page benchmark written by the author. | Larger, independently labelled corpus of real Malaysian scam pages. | Defensible estimates of field accuracy and false-positive rate. |
| Inference Capacity | One CPU worker; about 10 uncached inferences per second. | Distilled or quantised model, multiple workers or GPU inference. | Higher throughput and lower tail latency under load. |
| Mule Persistence | Local SQLite in WAL mode. | Client-server database with a distributed cache. | Supports multiple application instances and concurrent writers. |
| Government CTI | Simulated Semakmule database. | Authorised integration with NSRC 997 and Bank Negara Malaysia channels. | Registry reflects current national scam reports. |
| MLOps Pipeline | Static fine-tuned BERT checkpoint. | Continuous retraining with Airflow/MLflow. | Adapts to evolving phishing narratives and concept drift. |
| Deployment Model | Single ASGI process; in-memory sessions and rate limits. | Containerised replicas behind a load balancer with a shared session and rate-limit store. | Horizontal scaling and resilience to restarts. |

### 6.6 Conclusion

The Semantic Threat Intelligence and Mule Account Verification Engine developed in this project is a working, tested backend for client-side protection against Malaysian financial scams.

It combines a fine-tuned BERT URL classifier (Devlin et al., 2018) with brand-impersonation profiling, credential-form detection, a multilingual scam lexicon, deterministic regular-expression extraction and a relational mule registry, and it decides through a corroborated verdict engine rather than through any single model. The most important result of the project is the evidence for that design: on a labelled Malaysian benchmark, the original single-signal logic blocked 78.33% of legitimate pages, whereas the corroborated pipeline blocked none while detecting 95.00% of malicious pages.

The BERT model reaches 98.76% accuracy and a 97.80% F1-score on its 109,870-record hold-out set, but only 72.50% accuracy when used alone on Malaysian pages, a gap that illustrates why benchmark scores must not be mistaken for field performance. The service handles 22.4 requests per second without error at 50 concurrent users on CPU hardware, and 198 automated tests pass with 77% coverage. The registry is simulated and the benchmark is small, so the project demonstrates an approach to the problem of localised financial fraud in Malaysia (Royal Malaysia Police, 2024); it does not yet constitute a deployed defence against it.

In conclusion, this project connects deep learning with practical security engineering and with an honest evaluation of both. It contributes a tested architecture, a reproducible evaluation harness and a clear account of what remains to be done, in support of national cyber-resilience aims under the MyDIGITAL blueprint (Bank Negara Malaysia, 2023) and of the United Nations Sustainable Development Goals, specifically SDG 9 (Industry, Innovation, and Infrastructure) and SDG 16 (Peace, Justice, and Strong Institutions) (United Nations, 2015).
