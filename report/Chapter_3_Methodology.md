<!-- Generated from PhishGuard-AI_Project_1_&_2_Report_LiewYiLer.docx (v3.2.0, 16 November 2026). The Word document is the authoritative version; edit it, not this file. -->

# Chapter 3

## Methodology and Requirements Analysis

### 3.1 Introduction

Engineering a backend intelligence platform capable of intercepting zero-day financial phishing attacks and money mule networks requires a rigorous, scientifically grounded methodological framework. Unlike conventional software applications that rely purely on deterministic procedural logic, cybersecurity systems embedding deep neural networks operate under non-deterministic data distributions, adversarial evasion attempts, and extreme sub-second latency constraints.

This chapter formalises the engineering methodology, software development lifecycle, and requirements engineering procedures utilised to construct the **Semantic Threat Intelligence and Mule Account Verification Engine** developed as an individual module by Liew Yi Ler.

Specifically, this chapter details:

- The **Agile-MLOps Hybrid Software Development Life Cycle (SDLC)** combining two-week iterative development sprints with continuous Machine Learning Operations (CRISP-DM).
- Multi-tiered **Requirement Gathering Techniques**, encompassing Personal Data Protection Act 2010 (PDPA) regulatory reviews, semi-structured stakeholder simulations, and adversarial misuse case threat modelling.
- Detailed **Functional Requirements (FR)** and **Non-Functional Requirements (NFR)** categorised into structured subsystem matrices.
- The exact **Computational Hardware & Software Specifications** governing model training, GPU acceleration, and production ASGI inference.
- The complete **Data Science ETL Pipeline**, WordPiece subword tokenisation mechanics, and mathematical evaluation formulations (Binary Cross-Entropy Loss, Precision, Recall, F1-Score, and ROC-AUC metrics).

### 3.2 Software Development Life Cycle (SDLC): Agile-MLOps Hybrid Framework

#### 3.2.1 Rationale for the Agile-MLOps Hybrid Model

Traditional linear software engineering models such as the classic **Waterfall Model** mandate rigid, sequential progression through distinct phases (Requirements → Design → Implementation → Verification → Maintenance), relegating testing and validation strictly to the final stages of development.

In machine learning engineering, this linear paradigm fails catastrophically because deep learning models are intrinsically non-deterministic. A model's convergence, generalisation capability, loss optimisation, and inference latency cannot be predicted purely through static upfront design; they require continuous empirical validation, hyperparameter tuning, and data rebalancing (Symeonidis et al., 2022).

*[Figure: see the Word report]*

To resolve this limitation, this research engineered a **Hybrid Agile-MLOps Framework** integrating the rapid feature iteration of **Agile Scrum** (Beck et al., 2001) with the iterative data-centric lifecycle of the **Cross-Industry Standard Process for Data Mining (CRISP-DM)**.

By treating data preprocessing, tensor optimisation, PyTorch model serialising, and FastAPI endpoint benchmarking as integral components of every sprint cycle, the engineering team maintained continuous operational visibility over both software stability and AI detection accuracy.

*[Figure: see the Word report]*

#### 3.2.2 Agile-MLOps Sprint Breakdown and Technical Deliverables

The project was executed across four structured engineering sprints spanning two academic semesters, detailed in Table 3.1.

**Table 3.1: Agile-MLOps Sprint Breakdown and Technical Deliverables**

| Sprint Phase | Primary Focus Area | Key Technical Deliverables & Milestone Objectives |
| --- | --- | --- |
| Sprint 1 | Data Engineering & Requirements Analysis | • Ingested and cleaned the 549,346-record Kaggle phishing corpus and localised Malaysian scam datasets.<br>• Designed the normalised Third Normal Form (3NF) relational database schema in SQLite for money mule registries.<br>• Formulated functional, non-functional, and negative misuse requirements. |
| Sprint 2 | Deep Learning Model Training & Optimisation | • Instantiated pre-trained bert-base-uncased transformer architecture in PyTorch.<br>• Applied WordPiece subword tokenisation to raw DOM text and URL strings.<br>• Executed supervised fine-tuning with the AdamW optimiser, tracking loss convergence and early stopping.<br>• Evaluated model checkpoints across Precision, Recall, F1-Score, and ROC-AUC metrics. |
| Sprint 3 | FastAPI Microservice & Asynchronous Integration | • Developed asynchronous RESTful endpoints in FastAPI (POST /api/v1/analyze/semantics).<br>• Engineered pre-compiled Python Regex bytecode for 8 Malaysian bank formats.<br>• Implemented asynchronous database querying via aiosqlite in Write-Ahead Logging (WAL) mode.<br>• Integrated asyncio.to_thread() and asyncio.gather() for parallel, non-blocking execution. |
| Sprint 4 | System Hardening, Testing & SOC Deployment | • Constructed the automated Pytest Test Suite comprising 198 unit and integration test cases.
• Built the in-memory Trusted Domain Whitelist (frozenset) for 0ms false-positive avoidance.
• Deployed the Live SOC Dashboard with Server-Sent Events (SSE) telemetry, 24h GMT+8 velocity charts, and STIX 2.1 CTI exporters.

• Conducted stress testing and concurrency benchmarking on the Uvicorn ASGI server. |

### 3.3 Requirement Gathering & Threat Modelling Methodologies

To architect a resilient security system, requirements gathering must extend beyond standard user-centric functional features to encompass **negative requirements** explicitly defining the adversarial behaviours, injection vectors, and evasion tactics the system must actively neutralise.

*[Figure: see the Word report]*

#### 3.3.1 Document Analysis, Regulatory Compliance Review & Data Sovereignty

The requirement formulation commenced with a comprehensive audit of statutory data privacy frameworks and cybersecurity guidelines:

- **Malaysia Personal Data Protection Act 2010 (PDPA)**:Because the backend intercepts and analyses webpage DOM text directly from client browser sessions which may inadvertently include sensitive Personally Identifiable Information (PII) such as bank balances, NRIC numbers, or private communications compliance mandates strict **Data Sovereignty**. Transmitting unencrypted DOM payloads to commercial third-party cloud AI APIs (e.g., OpenAI ChatGPT, Anthropic Claude) represents a severe regulatory and privacy breach. This established the foundational requirement to **host the fine-tuned BERT model entirely on-premises**, guaranteeing that all semantic inference occurs strictly within the local security boundary without external data exfiltration.
- **OWASP Top 10 Web Application Security Standards (2021)**:Enforced strict input sanitisation rules to prevent A03:2021 - Injection vulnerabilities, mandating that all incoming DOM strings be scrubbed of executable JavaScript tags prior to NLP tokenisation.
- **PDRM CCID Semakmule Operational Specifications**:Analysed official Commercial Crime Investigation Department registry reporting formats to establish the precise numerical length, character boundaries, and institutional prefixes governing Malaysian financial accounts.

#### 3.3.2 Semi-Structured Stakeholder Simulation & "Security Fatigue" Mitigation

To understand real-world interaction workflows, semi-structured behavioural simulations were conducted across primary user cohorts:

- **General Banking Consumers**: Empirical observations demonstrated a pervasive prevalence of **"Security Fatigue"**. When presented with lengthy, technical security warnings or required to manually navigate to external portals (such as Semakmule) to verify seller account numbers, users almost universally bypass verification. This necessitated the creation of an **automated, zero-click verification engine** that extracts and checks financial credentials invisibly in the background.
- **SOC Analysts & Incident Responders**: Corporate administrators require structured, machine-readable threat feeds. This established the requirement for real-time Server-Sent Events (SSE) telemetry streaming and standardised **OASIS STIX 2.1 JSON** threat dossier export capabilities.

#### 3.3.3 Adversarial Threat Modeling & Misuse Case Engineering

To engineer proactive defensive countermeasures into the software architecture, the development team conducted **Adversarial Misuse Case Analysis** (Sindre & Opdahl, 2005). By modelling the tactical objectives of a cybercriminal attempting to subvert or crash the backend, explicit technical mitigations were derived, documented in Table 3.2.

*[Figure: see the Word report]*

**Table 3.2: Comprehensive Misuse Case Analysis and Derived Technical Mitigations**

| Misuse Scenario | Standard Use Case | Attacker Objective & Vector | Derived Architectural Mitigation |
| --- | --- | --- | --- |
| MC-01: API Resource Exhaustion (DoS) | Extension dispatches DOM payload to FastAPI backend for real-time analysis. | Botnet floods the API with large payloads to tie up CPU/GPU tensors and crash the ASGI server. | Rate Limiting & Async Offloading: Deployed SlowAPI fixed-window rate limiting (60 req/min per IP) and dispatched PyTorch tensors to dedicated thread pools (asyncio.to_thread). |
| MC-02: Typosquatting & Semantic Evasion | NLP model classifies webpage text to detect social engineering. | Attacker uses homoglyphs (rnaybank.com) or Manglish to bypass dictionary filters. | WordPiece Subword Tokenisation: Decomposes lookalikes into subwords (rn, ##ay, ##bank), capturing semantic roots across English, Bahasa Melayu, and Manglish. |
| MC-03: Malicious Payload Injection | DOM parser extracts text and account numbers for database query. | Attacker embeds SQL injection (' OR 1=1 --) or XSS payloads inside raw HTML or account fields. | Sanitisation & Parameterised SQL: Sanitises text via BeautifulSoup and executes all database queries using strictly parameterised aiosqlite SQL bindings (?). |
| MC-04: Model Extraction / Probing | Authorised endpoints return threat classification probabilities. | Attacker repeatedly queries API to map decision boundaries and clone model weights. | Bearer Token Authentication: Enforces HTTP Authorisation: Bearer <token> validation on all endpoints, rejecting unauthenticated probing with HTTP 401. |

### 3.4 Comprehensive System Requirements Specification

#### 3.4.1 Functional Requirements

The Functional Requirements explicitly define the programmatic endpoints, data processing routines, and verification pipelines executed by the Python backend.

**Table 3.3: Functional Requirements Specification Matrix**

| Subsystem Module | ID | Formal Functional Requirement Description |
| --- | --- | --- |
| API Gateway & Routing | FR 1.1 | The system shall expose an asynchronous POST /api/v1/analyze/semantics RESTful endpoint accepting JSON payloads containing target URL, sanitised DOM text, and metadata. |
|  | FR 1.2 | The system shall validate all incoming request bodies against strict Pydantic v2 schemas, immediately rejecting malformed payloads with HTTP 422 Unprocessable Entity. |
|  | FR 1.3 | The system shall execute semantic AI inference and SQLite database verification concurrently utilising asyncio.gather(), returning a unified aggregated verdict. |
|  | FR 1.4 | The system shall expose a POST /api/v1/analyze/quishing endpoint capable of ingesting base64-encoded images, decoding PayNet EMVCo QR matrices, and returning decoded URLs. |
| Whitelist & Pre-Filtering | FR 2.1 | The system shall evaluate incoming target domains against an in-memory frozenset containing 28 verified Malaysian banking institutions before executing AI inference. |
|  | FR 2.2 | If a domain matches the Trusted Whitelist, the system shall instantly bypass AI inference and return { verdict: "SAFE", risk_score: 0.00 } with < 1 ms latency. |
|  | FR 2.3 | The system shall maintain immunity rules for verified educational (.edu.my) and government (.gov.my) root domains to prevent false-alarm blocks on public portals. |
| Semantic Threat Engine | FR 3.1 | The system shall execute an ETL sanitisation pipeline using BeautifulSoup to strip <script>, <style>, and <svg> tags, isolating pure natural language text. |
|  | FR 3.2 | The system shall tokenise sanitised text using the BERT WordPiece tokeniser, truncating sequences to a maximum length of 128 tokens. |
|  | FR 3.3 | The system shall execute a forward tensor pass through the fine-tuned BERT model, applying Softmax to output a normalised threat probability in [0.0, 1.0]. |
|  | FR 3.4 | The system shall compute a Brand Impersonation Index (BII) utilising Levenshtein Distance algorithms to score domain similarity against top Malaysian banks. |
| Mule Account Scanner | FR 4.1 | The system shall execute pre-compiled Regular Expression bytecode to scan DOM text for continuous numerical strings matching 8 Malaysian bank formats. |
|  | FR 4.2 | The system shall query the SQLite mule_registry table asynchronously (aiosqlite) to match extracted numbers against known scammer records. |
|  | FR 4.3 | If a mule account is matched, the system shall append the bank name, report count, and flagged platform to the response, elevating the verdict to BLOCK_RENDER. |
|  | FR 4.4 | The system shall provide an administrative DELETE /api/v1/dashboard/mules/{id} endpoint with cyber-modal confirmation to revoke outdated mule records. |
| SOC Operations & CTI | FR 5.1 | The system shall expose a Server-Sent Events (GET /api/v1/dashboard/stream) endpoint broadcasting real-time threat telemetry events to active dashboard clients. |
|  | FR 5.2 | The system shall compute a rolling 24-hour Threat Velocity spectrum synchronised to Malaysia Standard Time (GMT+8) supporting 24h, 12h, and 8h intervals. |
|  | FR 5.3 | The system shall map live attack telemetry to 6 authentic global infrastructure datacentres (TM Net AS4788, Singtel AS7473, Cloudflare AS13335, etc.). |
|  | FR 5.4 | The system shall generate standardised OASIS STIX 2.1 JSON threat bundles, ArcSight CEF logs, and NSRC 997 / NFP account freeze dispatch dossiers. |

#### 3.4.2 Non-Functional Requirements

The Non-Functional Requirements establish rigorous operational constraints governing performance, security, availability, and maintainability.

**Table 3.4: Non-Functional Requirements Specification Matrix**

| Category | ID | Metric / Requirement | Target Specification & Verification Criteria |
| --- | --- | --- | --- |
| 1.0 Security | NFR 1.1 | API Authentication | All threat analysis endpoints shall mandate HTTP Authorisation: Bearer <token> authentication using a secret API key (a 256-bit random key is recommended for deployment). |
|  | NFR 1.2 | Data Sovereignty | All BERT NLP inference and DOM parsing shall execute strictly on local server hardware with zero data transmission to cloud AI services. |
|  | NFR 1.3 | Anti-DoS Rate Limiting | The backend shall enforce SlowAPI fixed-window rate limiting (60 requests/minute per client IP), dropping excess traffic with HTTP 429. |
| 2.0 Performance | NFR 2.1 | End-to-End Latency SLA | The complete pipeline (Pydantic validation, BERT NLP, and SQLite query) shall return a verdict in < 400 milliseconds. |
|  | NFR 2.2 | Model Singleton Pattern | The 440 MB PyTorch BERT model shall be loaded into RAM strictly once during ASGI lifespan startup, maintaining zero request I/O latency. |
|  | NFR 2.3 | In-Memory Whitelist SLA | Trusted domain whitelist lookups utilising Python frozenset hash tables shall resolve in < 1.0 millisecond. |
| 3.0 Reliability | NFR 3.1 | Event Loop Availability | CPU-bound tensor operations shall be offloaded via asyncio.to_thread(), ensuring the ASGI event loop achieves 99.9% availability. |
|  | NFR 3.2 | Database Concurrency | The SQLite database shall operate in Write-Ahead Logging (WAL) mode, so that readers are not blocked by the single writer. |
|  | NFR 3.3 | Test Suite Coverage | The codebase shall maintain a 100% pass rate across all 198 automated Pytest test cases in the continuous integration pipeline. |
| 4.0 Maintainability | NFR 4.1 | Open API Standard | The backend shall automatically generate interactive Swagger UI / OpenAPI 3.0 documentation at /docs reflecting all active schemas. |
|  | NFR 4.2 | Modular Architecture | The codebase shall maintain strict separation of concerns across /api/ routers, /services/ domain engines, and /tests/ suites. |

### 3.5 Computational Environment & Hardware/Software Specifications

#### 3.5.1 Hardware Specifications

Model training and high-concurrency ASGI inference mandate specific hardware acceleration parameters, documented in Table 3.5.

**Table 3.5: Hardware Specifications for Model Training & Production Inference**

| Computational Resource | Training Environment (Google Colab) | Production Inference Environment (Local Host) | Technical Justification |
| --- | --- | --- | --- |
| Processor (CPU) | Colab-provisioned virtual CPU (model not recorded in the training log) | AMD Ryzen 7 5700G, 8 cores / 16 threads | Runs the ASGI event loop and, during inference, 8 PyTorch intra-op threads. |
| System Memory (RAM) | Colab-provisioned (not recorded) | 32 GB DDR4 | Holds the 438 MB BERT weights and the YOLOv8n weights in memory with ample headroom. |
| Graphics Processing (GPU) | NVIDIA Tesla T4 (confirmed by the notebook's device check) | None used: CPU inference (PyTorch 2.12.1 CPU build) | The GPU was needed only for fine-tuning (3 h 03 min for 27,468 steps); inference was deliberately benchmarked on CPU to reflect commodity deployment. |
| Storage Subsystem | Google Drive mount for checkpoints | Local solid-state drive | Stores model checkpoints and the SQLite WAL database. |

#### 3.5.2 Software, Frameworks & Library Dependencies

The software ecosystem was selected based on performance, asynchronous capabilities, and open-source robustness, detailed in Table 3.6.

**Table 3.6: Software, Frameworks and Computational Libraries**

| Software / Framework | Version / Provider | Functional Application within Architecture |
| --- | --- | --- |
| Python | 3.14.3 (local inference and tests); 3.12 (Colab training) | Primary programming language utilising native asyncio for non-blocking coroutine execution. |
| FastAPI & Uvicorn | FastAPI 0.138.0 / Uvicorn ASGI | Implements the asynchronous RESTful API gateway and Server-Sent Events (SSE). |
| PyTorch & Hugging Face | PyTorch 2.12.1 (CPU) / Transformers 4.57.6 locally; Transformers 5.9.0 for training | Executes BERT forward passes (Paszke et al., 2019). Weights saved with 5.9.0 load unchanged on 4.57.6. |
| aiosqlite & SQLite | aiosqlite ≥ 0.20, SQLite 3 (WAL mode) | Provides non-blocking relational storage for the simulated PDRM CCID Semakmule registry. |
| BeautifulSoup4 & lxml | BS4 4.12+ | Executes DOM sanitisation, stripping executable scripts and isolating visible text. |
| Scikit-learn & Pandas | Scikit-learn 1.6.1 / Pandas 2.2.2 (Colab) | Train/test splitting and metric computation during fine-tuning. |
| OpenCV & Ultralytics | opencv-python 5.0 / Ultralytics 8.4.87 | QR decoding (cv2.QRCodeDetector) for quishing analysis; YOLOv8n logo detection. |
| SlowAPI & python-dotenv | SlowAPI ≥ 0.1.9 / python-dotenv 1.2.2 | Per-IP rate limiting; loading of PHISHGUARD_* settings from the .env file. |
| Pytest, pytest-asyncio, pytest-cov & Locust | Pytest 9.1.1 / pytest-cov ≥ 5 / Locust 2.44.4 | Automated test suite (198 tests), coverage measurement and load testing. |

### 3.6 Data Science Pipeline, ETL & Mathematical Evaluation Metrics

*[Figure: see the Word report]*

#### 3.6.1 Dataset Curation, ETL & WordPiece Tokenisation

The BERT model was fine-tuned on a single public corpus; no separate Malaysian training corpus was available, which is a limitation examined in Chapters 5 and 6:

- **Global Phishing Corpus (Kaggle)**: 549,346 labelled URL strings (Tiwari, n.d.) carrying the labels good (legitimate) and bad (phishing). The corpus contains URLs only, without page content.
- **Malaysian Evaluation Benchmark**: Malaysian scam content was not used for training. It was instead captured in a hand-curated evaluation benchmark of 120 labelled pages in English, Bahasa Melayu and Manglish (Section 5.5.2), used to test the complete pipeline and to tune its rule layer.
**ETL Sanitisation Pipeline**

Two preparation paths exist. For training, the URL strings were used as provided, after dropping rows with missing values and mapping the labels to integers. At inference time, raw DOM content received from the browser passes through the following Extract, Transform, Load (ETL) steps before the rule layer inspects it:

- **HTML Decomposition**: BeautifulSoup strips <script>, <style>, <noscript>, and SVG elements, extracting pure semantic text strings.
- **URL Normalisation**: Before the URL is passed to BERT, its scheme and any leading www. are removed so that the input has the same form as the training corpus.
- **Random Splitting**: The dataset was split with scikit-learn's train_test_split (test_size = 0.2, random_state = 42) into an 80% training set (439,476 records) and a 20% hold-out set (109,870 records, of which 31,200 are phishing). The split is random rather than temporal or domain-disjoint, which, as Section 5.5.1 discusses, makes the hold-out score optimistic.
**WordPiece Subword Tokenisation Mechanics**

The model input is encoded into numerical tensors utilising BERT's native **WordPiece Tokeniser** (Wu et al., 2016). WordPiece iteratively constructs a fixed vocabulary of V = 30,522 subword tokens.

When encountering an Out-Of-Vocabulary (OOV) typosquatted word (e.g., rnaybank), the algorithm decomposes the string using greedy longest-match prefix matching:

*[Figure: see the Word report]*

Each sequence is prefixed with the classification token [CLS] and terminated with [SEP], padded or truncated to a fixed maximum length of N = 128:

*[Figure: see the Word report]*

The tokeniser outputs two primary tensor matrices:

- **Input IDs **: Integer indices corresponding to token positions in the vocabulary.
- **Attention Mask **: Binary vector preventing the self-attention heads from computing weights over [PAD] tokens (for padding).

#### 3.6.2 Deep Learning Optimization & Mathematical Formulations

*[Figure: see the Word report]*

**1. Binary Cross-Entropy Loss **

The model is trained utilising cross-entropy loss over the two output logits (for two classes, equivalent to binary cross-entropy), measuring the divergence between the true binary label  and the predicted probability :

*[Figure: see the Word report]*

Where  represents the Sigmoid function, which for two classes is equivalent to the softmax applied to the model's two output logits .

**2. AdamW Optimiser with Weight Decay**

Network weights are updated utilising the **AdamW optimiser** (Loshchilov & Hutter, 2019), which decouples L_2 weight decay regularisation from gradient momentum updates:

*[Figure: see the Word report]*

#### 3.6.3 Mathematical Evaluation Metrics

*[Figure: see the Word report]*

To evaluate model performance on imbalanced cybersecurity datasets, evaluation relies on the mathematical formulations derived from the Confusion Matrix (Sokolova & Lapalme, 2009):

- **Precision (P)**: Measures the proportion of positively flagged websites that are genuinely malicious, quantifying protection against false alarms:
*[Figure: see the Word report]*

- **Recall / Sensitivity (R)**: Measures the proportion of actual phishing websites successfully detected by the model, quantifying resilience against threat evasion:
*[Figure: see the Word report]*

- **Specificity / True Negative Rate (S)**: Measures the model's ability to correctly identify benign banking portals:
*[Figure: see the Word report]*

- **Balanced F1-Score (F_1)**: The harmonic mean of Precision and Recall, providing a single balanced metric that penalises extreme skews in either metric:
*[Figure: see the Word report]*

- **Receiver Operating Characteristic - Area Under the Curve (ROC-AUC)**: Measures the integral of the True Positive Rate (TPR) plotted against the False Positive Rate (FPR) across all classification thresholds :
*[Figure: see the Word report]*

An AUC approaching 1.0 indicates exceptional mathematical separability between phishing and legitimate web semantics (Fawcett, 2006).

### 3.7 Chapter Summary

This chapter has established the methodological engineering foundation, rigorous system requirements, and data science mathematical formulations governing the **PhishGuard-AI** backend platform.

Key methodologies and analytical outputs established in this chapter include:

- Agile-MLOps Hybrid Lifecycle: Structured development into four focused sprints combining rapid API refactoring with empirical machine learning tuning and automated Pytest CI/CD (198/198 tests passing).
- **Adversarial Requirements & Misuse Modelling**: Formulated legal constraints (PDPA data sovereignty requiring on-premises BERT deployment) and derived defensive mitigations against DoS flooding, typosquatting evasion, and SQL injection.
- **Comprehensive Functional & Non-Functional Requirements**: Mapped 19 Functional Requirements across 5 subsystems and established strict Non-Functional SLAs (< 400 ms latency, Model Singleton pattern, and WAL mode concurrency).
- **Data Science ETL & Tokenisation Pipeline**: Detailed BeautifulSoup HTML sanitisation, BERT WordPiece subword decomposition, AdamW loss optimisation, and confusion matrix evaluation metrics.
These methodological specifications serve as the direct blueprint for **Chapter 4: System Design**, which translates these analytical requirements into concrete software architecture diagrams, database relational schemas, and asynchronous API contract specifications.
