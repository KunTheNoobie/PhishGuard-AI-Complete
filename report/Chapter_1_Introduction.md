<!-- Generated from PhishGuard-AI_Project_1_&_2_Report_LiewYiLer.docx (v3.2.0, 16 November 2026). The Word document is the authoritative version; edit it, not this file. -->

**Design and Development of ‘PhishGuard-AI’: A Multi-Modal Integrated Financial Scam Detection System utilising Hybrid Deep Learning Semantic Threat Intelligence and Mule Account Verification Engine**

By

Liew Yi Ler

*[Figure: see the Word report]*

FACULTY OF COMPUTING AND 

INFORMATION TECHNOLOGY

TUNKU ABDUL RAHMAN UNIVERSITY OF MANAGEMENT AND TECHNOLOGY

KUALA LUMPUR

ACADEMIC YEAR

2026/2027

Design and Development of ‘PhishGuard-AI’: A Multi-Modal Integrated Financial Scam Detection System utilising Hybrid Deep Learning Semantic Threat Intelligence and Mule Account Verification Engine

By

Liew Yi Ler

Supervisor: Dr. Ng Yen Phing

A project report submitted to the 

Faculty of Computing and Information Technology  

in partial fulfillment of the requirement for the

Bachelor of Information Technology (Honours) in Information Security

Academic Year 2026/2027

Faculty of Computing and Information Technology  

Tunku Abdul Rahman University of Management and Technology

Kuala Lumpur

**Copyright by Tunku Abdul Rahman University of Management and Technology.**

All rights reserved.  No part of this project documentation may be reproduced, stored in retrieval system, or transmitted in any form or by any means without prior permission of Tunku Abdul Rahman University of Management and Technology.

**Declaration**

The project submitted herewith is a result of my own efforts in totality and in every aspect of the project works.  All information that has been obtained from other sources had been fully acknowledged.  I understand that any plagiarism, cheating or collusion or any sorts constitutes a breach of Tunku Abdul Rahman University of Management and Technology (TAR UMT)  rules and regulations and would be subjected to disciplinary actions.

*[Figure: see the Word report]*

_______

Liew Yi Ler

Bachelor of Information Technology (Honours) in Information Security

Student ID: 25WMR09747

**Abstract**

Financial scams, deceptive credential harvesting, and sophisticated social engineering campaigns are among the most damaging cybersecurity threats to Malaysia's rapidly evolving digital economy. Traditional defensive mechanisms rely overwhelmingly on static, signature-based blacklists (e.g., DNSBL, SURBL, Google Safe Browsing), which inherently suffer from severe time-to-protect latency and consistently fail to mitigate short-lived, ephemeral "Zero-Day" phishing campaigns and context-aware phishing kits. To decisively overcome these critical vulnerabilities, the PhishGuard-AI system was proposed as a multi-modal client-server cybersecurity platform. This Project 2 final dissertation and research report details the comprehensive implementation, empirical evaluation, mathematical formulation, architectural system design, and evaluation of the central intelligence core: the Semantic Threat Intelligence and Mule Account Verification Engine developed as an individual module by Liew Yi Ler.

The primary objective of this module is to move web endpoint defence from reactive blacklist matching towards proactive, real-time classification. A Transformer-based model, Bidirectional Encoder Representations from Transformers (BERT, bert-base-uncased), was fine-tuned for one epoch on 439,476 labelled URLs from a public phishing corpus and reached 98.76% accuracy and a 97.80% F1-score on the 109,870-URL hold-out split. Evaluation on a purpose-built benchmark of 120 Malaysian pages (English, Bahasa Melayu and Manglish) showed, however, that this URL classifier is not reliable enough to act on alone: used by itself it flagged 43% of the legitimate pages. The engine therefore treats BERT as one supporting signal inside a corroborated verdict engine that also weighs brand-in-hostname and look-alike domain evidence (for example rnaybank2u.com), credential-form detection, a multilingual scam lexicon and structural URL heuristics, while a Trusted Domain Whitelist exempts official financial portals.

To combat rampant peer-to-peer e-commerce and social media fraud in Malaysia, an automated **Mule Account Verification Engine** was developed. Utilising pre-compiled Regular Expression (Regex) bytecode optimised for 8 major Malaysian banking account formats (Maybank, CIMB, Public Bank, RHB, Hong Leong, AmBank, Bank Islam, Bank Rakyat), the engine autonomously scans visible webpage text and cross-references extracted financial credentials against a normalised SQLite 3NF database simulating the Royal Malaysia Police (PDRM) CCID Semakmule registry. Furthermore, the backend integrates optical Quishing (QR Phishing) decoding via OpenCV cv2.QRCodeDetector() to unmask obfuscated PayNet EMVCo DuitNow payment proxy strings.

These capabilities are orchestrated through an asynchronous FastAPI microservice on a Uvicorn ASGI server. PyTorch inference runs in worker threads (asyncio.to_thread) in parallel with asynchronous database I/O (asyncio.gather), and the Manifest V3 Chrome Extension receives a BLOCK_RENDER or SAFE verdict together with the reasons for it. On the Malaysian benchmark the completed pipeline reached 97.50% accuracy, 100% precision and 95.00% recall with no false positives, compared with 57.50% accuracy and a 78.33% false-positive rate before the decision logic was redesigned. In a 60-second Locust load test with 50 concurrent users on CPU-only hardware, the service handled 22.4 requests per second with no errors, a median response time of 13 ms and a 95th percentile of 370 ms. An integrated Security Operations Centre (SOC) dashboard, protected by administrative authentication, provides Server-Sent Events telemetry, registry management and threat-intelligence exports. A suite of 198 automated tests passes in full with 77% statement and branch coverage. The benchmark is small and was authored for this project, so these results demonstrate correct behaviour on representative Malaysian scam patterns rather than field accuracy.

**Keywords**: Phishing Detection, BERT Natural Language Processing, Money Mule Account Verification, Semakmule Registry, FastAPI Microservices, Quishing Forensics, Threat Intelligence, Zero-Trust Endpoint Security.

**Acknowledgement**

First and foremost, I would like to express my deepest gratitude and highest respect to my Final Year Project supervisor, Dr. Ng Yen Phing, for continuous mentorship, technical insights, and academic guidance throughout the entire lifecycle of this research. Dr. Ng's expertise in information security, threat intelligence, and secure software engineering significantly elevated the academic rigour, architectural integrity, and practical viability of this project.

I would also like to extend my sincere appreciation to the Faculty of Computing and Information Technology (FOCS) at Tunku Abdul Rahman University of Management and Technology (TAR UMT) for providing state-of-the-art computational laboratories, software tooling, and an exceptional academic environment that fostered the success of this project.

A special acknowledgement is extended to my project partner, Cheon Jie Han, for his dedicated collaboration on the frontend client-side browser extension and visual convolutional neural network (CNN) logo detection module. The seamless integration between the client-side Manifest V3 architecture and the backend FastAPI AI microservice stands as a testament to our effective team synergy and rigorous parallel engineering.

Finally, I dedicate my deepest appreciation to my beloved family and friends for their unwavering patience, moral support, and boundless encouragement throughout my academic journey. Their steadfast belief in my aspirations provided the continuous motivation required to bring this dissertation to fruition.

**Table of Content**

# Chapter 1

## Introduction

### 1.1 Background of the Study

In the contemporary era of the Fourth Industrial Revolution (IR 4.0), the global financial ecosystem has undergone an irreversible structural transformation towards decentralised, frictionless, and instantaneous digital transactions. Within Malaysia, aggressive national digitalisation blueprints most notably the **MyDIGITAL Malaysia Digital Economy Blueprint** and the **Bank Negara Malaysia (BNM) Financial Sector Blueprint 2022–2026** have systematically catalysed the nationwide adoption of real-time electronic payment rails. The pervasive deployment of national infrastructure such as the DuitNow real-time payment switch (operated by Payments Network Malaysia Sdn Bhd / PayNet), Touch 'n Go (TNG) eWallet, and integrated mobile banking applications has expanded digital financial inclusion across diverse socio-economic demographics in both urban and rural communities (Bank Negara Malaysia, 2023).

*[Figure: see the Word report]*

However, this rapid digital transformation has drastically enlarged the attack surface accessible to cybercriminal syndicates, precipitating an unprecedented surge in financial cybercrime. As the technical barrier to entry for conducting digital transactions drops, internet users a substantial proportion of whom possess limited formal cybersecurity awareness are routinely targeted by sophisticated, multi-stage social engineering campaigns. When confidential banking credentials, Transaction Authorisation Codes (TAC), and One-Time Passwords (OTP) are illicitly harvested, the ramifications are catastrophic. Beyond catastrophic personal financial losses suffered by individual victims, these breaches inflict lasting reputational damage on national financial institutions and critically erode public confidence in the digital banking ecosystem.

Empirical statistics released by **CyberSecurity Malaysia**, the **National Scam Response Centre (NSRC 997)**, and the **Royal Malaysia Police (PDRM) Commercial Crime Investigation Department (CCID)** reveal that online financial fraud and deceptive phishing currently represent the single largest cybercrime category in Malaysia. Financial losses stemming from telecommunication fraud, deceptive investment schemes, e-commerce scams, and phishing campaigns exceeded **RM1.3 billion in 2023**, with subsequent years exhibiting an aggressive upward trajectory (CyberSecurity Malaysia, 2024; Royal Malaysia Police, 2024).

Historically, phishing attacks were characterised by rudimentary, mass-distributed spam emails containing generic salutations and conspicuous orthographic errors that were readily flagged by heuristic spam filters. Today, cybercrime syndicates operate as industrialised enterprises utilising modern Phishing-as-a-Service (PhaaS) frameworks (e.g., EvilProxy, Modlishka), Domain Generation Algorithms (DGA), fast-flux DNS hosting networks, and generative Artificial Intelligence (AI) to synthesise contextually flawless, highly persuasive attack narratives (Alkhalil et al., 2021). Attackers deploy sophisticated brand clones mimicking Malaysia's premier banking institutions including Malayan Banking Berhad (Maybank), CIMB Bank Berhad, Public Bank Berhad, and government statutory bodies such as the Employees Provident Fund (KWSP/EPF) and the Inland Revenue Board (LHDN).

To confront these national security challenges, the **PhishGuard-AI** project was initiated to design and engineer a proactive, multi-modal browser security suite. Rather than relying on reactive blacklists, PhishGuard-AI embeds Artificial Intelligence directly at the endpoint to autonomously inspect, predict, and intercept emerging cyber threats. Because of the vast interdisciplinary complexity of this system, the engineering responsibilities were strategically partitioned into two collaborative modules:

- **Module 1 (Author - Liew Yi Ler)**: Semantic Threat Intelligence and Mule Account Verification Engine (Backend Server & AI Core).
- **Module 2 (Collaborator - Cheon Jie Han)**: Visual Identity Analysis and Client-Side Browser Integration (Frontend Extension & CNN Vision).
This dissertation focuses exclusively on the backend intelligence engine developed by **Liew Yi Ler**. By combining fine-tuned **Bidirectional Encoder Representations from Transformers (BERT)** Natural Language Processing with deterministic Regular Expression (Regex) bytecode execution and asynchronous database verification, this backend establishes a zero-trust browsing environment that neutralises financial fraud at sub-second speeds.

### 1.2 Problem Statement

Despite continuous advancements in network perimeter firewalls and browser sandboxing, end-users remain acutely vulnerable to financial scams due to four fundamental architectural deficiencies in contemporary defensive technologies:

*[Figure: see the Word report]*

#### 1.2.1 The Latency of Static Blacklists Against Zero-Day Ephemeral Threats

Traditional web security architectures rely predominantly on deterministic, signature-based blacklists (e.g., Google Safe Browsing, DNSBL, PhishTank, Spamhaus). While computationally inexpensive, blacklists operate purely reactively. To flag a malicious domain, the URL must first be reported by a victim, crawled by security bots, mathematically analysed, and propagated globally to client caches.

Measurement of real campaigns shows how costly this delay is: Oest et al. (2020) found that anti-phishing entities detected an attack on average nine hours after its first victim, in campaigns that were on average over within 21 hours, and that a further delay passed before browser warnings reached their peak. Consequently, early victims visiting a "Zero-Day" phishing site receive zero protection from standard browser safeguards.

#### 1.2.2 Evasion via Semantic Manipulation, Multilingual Triggers, and Typosquatting

Modern threat actors systematically bypass string-matching and keyword-density filters (e.g., TF-IDF) by employing sophisticated semantic manipulation. Attackers craft persuasive Document Object Model (DOM) content embedded with psychological coercion triggers (e.g., "Akaun bank anda telah digantung! Sila sahkan TAC dalam masa 5 minit"), artificial countdown timers, and fake security trust badges.

Furthermore, in multicultural regions like Malaysia, phishing campaigns heavily exploit multilingual colloquialisms (Bahasa Melayu, English, and localised Manglish) that generic English-centric classifiers fail to evaluate. Threat actors also exploit Internationalised Domain Name (IDN) homoglyph attacks and subtle typosquatting permutations (e.g., replacing m with rn to register rnaybank.com), evading syntactic filters while successfully deceiving human visual perception (Sahingoz et al., 2019).

#### 1.2.3 High Friction in the Verification of Localised Mule Accounts ("Keldai Akaun")

In domestic e-commerce fraud and peer-to-peer marketplace scams (e.g., Facebook Marketplace, Telegram channels, Mudah.my), syndicates route illicit proceeds through compromised third-party bank accounts known colloquially as "Keldai Akaun" (Money Mule Accounts). While the Royal Malaysia Police (PDRM) CCID operates the public Semakmule database, verifying a beneficiary account requires a user to manually copy the account number, navigate away from the transaction page, access the external government portal, complete a CAPTCHA challenge, and interpret the record (Royal Malaysia Police, 2023).

This high-friction, manual process is almost never performed by average consumers during fast-paced digital transactions. Consequently, flagged money-mule accounts operate unimpeded directly within the user's browser viewport without triggering any automated endpoint alerts.

#### 1.2.4 Degradation of the CIA Triad in Digital Transactions

A single successful phishing interaction triggers a cascading failure that obliterates the foundational security principles of the **CIA Triad (Confidentiality, Integrity, and Availability)**:

- **Confidentiality**: Coercing users into disclosing passwords, NRIC numbers, and TAC/OTP codes on fraudulent forms grants unauthorised adversaries access to private financial data.
- **Integrity**: With compromised authentication tokens, attackers manipulate transaction states, modify standing beneficiary instructions, and execute unauthorised wire transfers.
- **Availability**: Fraud syndicates frequently lock legitimate users out of their online banking accounts by altering recovery email addresses and credentials, inducing a total denial of service for the victim's liquid assets.
*[Figure: see the Word report]*

### 1.3 Objectives of the Project

The primary goal of this research project is to architect, develop, and evaluate an intelligent, high-throughput backend microservice platform capable of real-time semantic analysis and automated financial credential verification. The specific technical objectives established for this individual module are:

- **To Engineer a Semantic Threat Intelligence Engine Utilising Fine-Tuned BERT and Corroborating Multi-Lingual Signals**:Train and fine-tune a Bidirectional Encoder Representations from Transformers (bert-base-uncased) deep learning model on a large public corpus of labelled phishing and legitimate URLs, supported by brand-impersonation profiling, credential-form detection and a multilingual (English, Bahasa Melayu, and Manglish) scam lexicon. The objective is to achieve high precision () in detecting typosquatted domains, urgent psychological triggers and credential-harvesting pages, with model inference in roughly 100 milliseconds on commodity hardware.
- **To Design and Implement an Automated Mule Account Verification Engine for Malaysian Financial Formats**:Develop a low-latency credential extraction algorithm utilising pre-compiled Regular Expression (Regex) bytecode to scan webpage DOM text for 10-to-14-digit bank account formats across 8 major Malaysian banking institutions. Integrate an asynchronous SQLite 3NF relational database simulating the PDRM CCID Semakmule registry to flag verified mule accounts in real time with zero manual user friction.
- **To Architect a High-Concurrency, Low-Latency FastAPI Microservice with Enterprise SOC Capabilities**:Construct an asynchronous RESTful backend utilising FastAPI and Uvicorn that orchestrates AI tensor calculations (asyncio.to_thread) and database I/O concurrently using asyncio.gather(). The microservice must achieve an end-to-end response time under 400 milliseconds, provide a Server-Sent Events (SSE) live telemetry stream, host a 24-hour Threat Velocity timeline in Malaysia Time (GMT+8), and expose standardised CTI incident exporters (OASIS STIX 2.1 JSON, CEF, Syslog, and NSRC 997 dispatch formats).

#### 1.3.1 Research Questions (RQ)

To systematically direct the scientific investigation and establish rigorous empirical boundaries for this study, three core Research Questions (RQs) are formulated, corresponding directly to the Research Objectives:

- **Research Question 1 (RQ1 - Contextual Semantic Evasion Resilience)**:How effectively can a fine-tuned Bidirectional Encoder Representations from Transformers (BERT) model, trained on a public phishing URL corpus and applied to multi-lingual (English, Bahasa Melayu, and Manglish) Malaysian scam content, detect contextual social engineering coercion, urgent psychological triggers, and typosquatted domains compared to traditional lexical and keyword heuristics, while sustaining an inference latency under 100 milliseconds?
- **Research Question 2 (RQ2 - Deterministic Mule Credential Extraction)**:To what degree can pre-compiled regular expression (Regex) bytecode execution coupled with an asynchronous relational database architecture (SQLite 3NF in WAL mode) automate the zero-friction detection and forensic logging of Malaysian commercial bank mule accounts directly from browser DOM content?
- **Research Question 3 (RQ3 - High-Concurrency Asynchronous Orchestration)**:How can an asynchronous ASGI microservice pipeline (utilising FastAPI, asyncio.to_thread(), and asyncio.gather()) orchestrate concurrent deep learning tensor computations and relational database transactions to achieve an end-to-end verdict latency of under 400 milliseconds while streaming real-time CTI telemetry to enterprise SOC dashboards?

### 1.4 Solution: The Proposed Framework

To systematically resolve the challenges outlined in Section 1.2, the PhishGuard-AI backend implements a multi-layered, asynchronous intelligence pipeline:

*[Figure: see the Word report]*

#### 1.4.1 Securing Web Browsing with Dynamic Semantic BERT Analysis

To neutralise the zero-day latency of static blacklists, PhishGuard-AI deploys a fine-tuned BERT Transformer neural network. When an end-user navigates to an unverified webpage, the client extension extracts the sanitised DOM text and dispatches it to the FastAPI microservice.

The BERT engine applies WordPiece tokenisation to the page URL and produces a phishing probability from its bidirectional contextual embeddings. Because the model was fine-tuned on URL strings, it is strongest at recognising deceptive hostnames and paths; coercive wording in the page body (for example a suspension notice demanding immediate TAC entry) is detected by the accompanying scam lexicon and credential-form detector. To ensure that authentic banking websites are never delayed or blocked, an in-memory Trusted Domain Whitelist (frozenset) bypasses the neural network for verified domains (e.g., maybank2u.com.my, pbebank.com).

#### 1.4.2 Preventing Fraud via Automated Mule Credential Verification

To eliminate the manual friction of the PDRM Semakmule lookup, the backend incorporates an automated regex extraction and database verification engine. As webpage content is ingested, the engine executes pre-compiled regular expressions calibrated to the specific account number lengths and prefix patterns of 8 major Malaysian banks.

Extracted account numbers are immediately queried against an internal SQLite database operating in **Write-Ahead Logging (WAL)** mode. If a match is detected, the API immediately injects the mule account's fraud history, report count, and flagged platform into the JSON response payload, triggering an instantaneous block before funds can be transferred.

#### 1.4.3 Enhancing System Availability via Asynchronous Microservices

Heavy deep learning models executed naively inside web servers block the main application event loop, leading to server thread exhaustion and high latency. To preserve responsiveness, the backend is built on **FastAPI** running on the **Uvicorn** Asynchronous Server Gateway Interface (ASGI).

Computational PyTorch tensors are dispatched to separate thread pools using asyncio.to_thread(), while database queries and heuristics run concurrently via asyncio.gather(). This architecture keeps the service responsive while inference is in progress; measured latencies are reported in Section 5.5.3.

#### 1.4.4 Live SOC Telemetry, Geographic Attack Radar & CTI Sharing

The backend features an integrated Threat Intelligence Dashboard (/dashboard/) powered by Server-Sent Events (SSE) and protected by administrative authentication. The dashboard visualises detections as they occur, renders a 24-hour Threat Velocity view in Malaysia Standard Time (GMT+8), and presents an illustrative geographic view in which each record is assigned to one of six representative hosting regions; the system does not resolve the real network origin of a threat.

For institutional defence, the backend provides 1-click incident escalation to the **National Scam Response Centre (NSRC 997)** and automated threat intelligence sharing via **OASIS STIX 2.1 JSON bundles**, ArcSight CEF, and RFC 5424 Syslog feeds.

*[Figure: see the Word report]*

### 1.5 Target Market & Stakeholder Analysis

PhishGuard-AI is engineered to deliver pervasive protection across diverse stakeholder tiers in the digital ecosystem:

**Primary Users:**

- **General Public and Elderly Internet Banking Consumers**:Individuals who frequently utilise web browsers for e-commerce, bill payments, and online banking but lack formal technical training to detect homoglyph attacks, analyse SSL/TLS certificate chains, or identify subtle linguistic coercion. Their core requirement is an autonomous, "zero-click" endpoint security layer that intercepts threats seamlessly without interrupting normal navigation.
- **Small and Medium Enterprise (SME) Personnel**:Employees in procurement, accounting, and administrative roles who manage digital invoices and wire transfers. This demographic is heavily targeted by Business Email Compromise (BEC) and invoice redirection scams that utilise newly registered domains designed to bypass standard corporate firewalls.
**Secondary Users & Institutional Beneficiaries:**

- **Commercial Banks & Financial Institutions (Maybank, CIMB, Public Bank, RHB, PayNet)**:Security Operations Centres (SOC) and Fraud Risk teams seeking to curb customer credential theft, brand spoofing, and dispute liability claims. They benefit directly from an ecosystem that intercepts money-mule transfers before funds leave the consumer's account.
- **Cybersecurity Operations & Law Enforcement Agencies (PDRM CCID, CyberSecurity Malaysia, NSRC 997)**:Incident response analysts who require structured, forensically sound digital dossiers. The platform auto-formats telemetry into standardised law enforcement dispatch records and STIX 2.1 cyber threat intelligence feeds.
*[Figure: see the Word report]*

### 1.6 Advantages & Novel Academic Contributions

The engineering of the PhishGuard-AI backend provides substantial practical and academic contributions to the domain of cybersecurity:

- **Enhanced Edge-Adjacent Data Confidentiality and Privacy**:By deploying lightweight, fine-tuned BERT models on a localised, self-hosted microservice rather than dispatching user DOM text to commercial third-party cloud LLM APIs (e.g., OpenAI, Anthropic), the system guarantees that sensitive user form inputs and session tokens are never leaked to external third parties.
- **Proactive Elimination of Zero-Day Phishing Windows**:Shifting threat detection from reactive signature matching to semantic intent classification neutralises zero-day phishing sites within milliseconds of domain instantiation, eliminating the 4-to-48-hour vulnerability window inherent to static blacklists.
- **Frictionless Money-Mule Account Interception**:Automating regex credential extraction and SQLite database verification directly within the backend pipeline removes the friction of manual government registry lookups, directly addressing the core vector of domestic peer-to-peer financial fraud.
- **Direct Alignment with United Nations Sustainable Development Goals (UN SDGs)**:This research directly advances **UN SDG 16 (Peace, Justice, and Strong Institutions)** by providing technological tooling to dismantle illicit cybercrime syndicates, and **UN SDG 9 (Industry, Innovation, and Infrastructure)** by strengthening the resilience and reliability of digital banking infrastructure (United Nations, 2015).

### 1.7 Project Plan & Management

#### 1.7.1 Project Scope & Separation of Concerns

To achieve high-quality software engineering standards, the PhishGuard-AI project was partitioned into two distinct engineering scopes between the two project members:

- **Backend Server & AI Core (Author: Liew Yi Ler - Module 1)**: Covers model fine-tuning, BERT semantic inference, regex credential extraction, SQLite 3NF mule registry database, FastAPI ASGI routing, SSE telemetry streaming, and CTI exporters.
- **Frontend Client & Computer Vision (Collaborator: Cheon Jie Han - Module 2)**: Covers Manifest V3 Chrome extension service workers, DOM extraction, popup UI, full-screen BLOCK_RENDER shield overlay, and CNN/YOLOv8 visual logo detection.
The detailed module breakdown and task allocation is formalised in Table 1.1.

**Table 1.1: Description of System Modules and Task Allocation**

| System Module | Detailed Engineering Scope | Assigned Member |
| --- | --- | --- |
| Semantic Threat Intelligence Engine | • Fine-tunes and evaluates BERT (bert-base-uncased) on 549,346 labelled URLs (80/20 split).<br>• Implements DOM sanitisation, WordPiece tokenisation and softmax probability output.<br>• Implements the corroborated verdict engine (rules R1–R6), brand profiler, multilingual scam lexicon and Trusted Domain Whitelist. | Liew Yi Ler (Module 1 - Author) |
| Mule Account Verification Engine | • Engineers pre-compiled Python Regex patterns matching 8 Malaysian bank account formats plus DuitNow phone and NRIC proxies.<br>• Designs and maintains the SQLite database (WAL mode): mule_registry, threat_telemetry and the mule_reports review queue.<br>• Develops real-time matching and forensic aggregation logic. | Liew Yi Ler (Module 1 - Author) |
| Backend API Gateway & SOC Operations | • Constructs the asynchronous FastAPI microservice with Bearer-token authentication, rate limiting and administrative session authentication for the dashboard.<br>• Implements asyncio.to_thread and asyncio.gather for parallel execution.<br>• Builds the Live SOC Dashboard, SSE event stream, 24h GMT+8 timeline, and STIX 2.1 CTI exporter. | Liew Yi Ler (Module 1 - Author) |
| Visual Identity Analysis (CNN / YOLOv8) | • Trains a YOLOv8n convolutional detector (Jocher et al., 2023) on a synthetic logo dataset (1,839 images generated from 39 official-site screenshots of five banks).<br>• Identifies brand impersonation of Malaysian commercial banks via screenshot logo and domain mismatch. | Cheon Jie Han (Module 2) |
| Client-Side Browser Integration | • Develops the Manifest V3 Google Chrome Extension utilising Service Workers and Content Scripts.<br>• Implements deep DOM/Shadow DOM extraction and the high-impact Red Defence Shield overlay. | Cheon Jie Han (Module 2) |

*[Figure: see the Word report]*

#### 1.7.2 Milestones & Project Schedule

The project followed the official faculty calendar for Project I (session 202605, June 2025 intake, Entry Year 2) and Project II (session 202609, short semester 2 November to 20 December 2026). The milestones and their dates are listed in Table 1.2.

**Table 1.2: Project Milestones and Schedule**

| Project Phase / Activity | Expected Deliverable / Outcome | Completion Timeline |
| --- | --- | --- |
| Project I — Supervisor Approach | Identify a supervisor and agree the project area (January semester, 26/01/2026 – 01/05/2026). | 27 February 2026 |
| Project I — Supervisor Assignment | Formal assignment of supervisor by the faculty. | 16 March 2026 |
| Project Proposal Submission (Forms 1, 2, 3) | Formalise project objectives, technical scope and preliminary system architecture. | 10 April 2026 |
| Proposal Moderation | Moderator assessment of the proposal; feedback incorporated into the threat model and scope. | 12 June 2026 |
| Submission of Chapter 1: Introduction | Background study, problem statements, objectives, scope and project plan (May semester, 15/06/2026 – 20/09/2026). | 26 June 2026 |
| Submission of Chapter 2: Literature Review | Critical evaluation of phishing detection approaches, Transformer models and mule-account verification. | 10 July 2026 |
| Submission of Chapter 3: Methodology | Agile-MLOps methodology, functional and non-functional requirements, evaluation metrics. | 24 July 2026 |
| Submission of Chapter 4: System Design | System architecture, UML diagrams, database schema and API contract specifications. | 14 August 2026 |
| Submission of Project I Portfolio | Interim documentation, prototype evidence and code repository for evaluation. | 4 September 2026 |
| Initial System Preview | Demonstration of the working prototype to the supervisor. | 11 September 2026 |
| Project I Mark Entry (Intranet) | Completion of Project I assessment. | 18 September 2026 |
| Project II — Test Plan & System Preview with Supervisor | Week 2 of the short semester. Scheduled for 13 November 2026 and rescheduled to 17 November 2026 following supervisor reassignment. | 17 November 2026 |
| Final System Testing with Supervisor and Moderator | Week 3. Full functional demonstration, benchmark evaluation and load-test evidence. | 20 November 2026 |
| Make Good Testing (if applicable) | Week 4. Re-demonstration of any item not accepted during final testing. | 27 November 2026 |
| Submission of Draft FYP Report (individual) | Week 5. Complete six-chapter draft with appendices and empirical results. | 4 December 2026 |
| Submission of Final FYP Report (individual) and Deliverables | Week 6. Final report, source repository, poster and presentation. | 11 December 2026 |
| Project II Mark Entry (Intranet) | Week 7. Completion of Project II assessment. | 18 December 2026 |

#### 1.7.3 Hybrid Agile-MLOps Software Engineering Model

Standard Software Development Life Cycles (e.g., Waterfall) are incapable of accommodating the empirical, non-linear iterations required in machine learning model development. Consequently, this project adopted a **Hybrid Agile-MLOps Engineering Model**:

*[Figure: see the Word report]*

- **Agile Framework**: Governs microservice architecture, API endpoint routing, and dashboard development through two-week iterative sprints, allowing flexible adaptation as new evasion tactics were uncovered.
- **Machine Learning Operations (MLOps)**: Integrates continuous data curation, hyperparameter optimisation, loss convergence monitoring, and rigorous model evaluation (Precision, Recall, F1-Score, Confusion Matrices) directly into each sprint cycle (Kreuzberger et al., 2023).
*[Figure: see the Word report]*

### 1.8 Project Team & Organisational Structure

To guarantee project success and strict accountability, the responsibilities between the two team members were clearly established as outlined in Table 1.3.

**Table 1.3: Project Team Organisation & RACI Matrix**

| System Function / Engineering Layer | Backend Server & AI Core (Liew Yi Ler) | Frontend Client & Extension (Cheon Jie Han) |
| --- | --- | --- |
| BERT Semantic NLP Model Fine-Tuning | Accountable & Responsible | Consulted |
| Mule Account Regex & 3NF SQLite Database | Accountable & Responsible | Informed |
| FastAPI Microservice & Asynchronous Orchestration | Accountable & Responsible | Informed |
| Live SOC Dashboard, SSE Stream & Geo Radar | Accountable & Responsible | Informed |
| Visual Brand Classifier (CNN / YOLOv8) | Informed | Accountable & Responsible |
| Manifest V3 Chrome Extension & Service Worker | Consulted | Accountable & Responsible |
| DOM Deep Extraction & Red Shield Overlay | Consulted | Accountable & Responsible |
| End-to-End Client-Server System Integration | Jointly Responsible | Jointly Responsible |

### 1.9 Chapter Summary & Evaluation

This introductory chapter has established the foundational rationale, theoretical background, problem space, and technical scope of the **PhishGuard-AI** research project. Modern financial cybercrime in Malaysia has outpaced traditional static blacklists, necessitating an AI-driven paradigm shift towards real-time semantic analysis and automated money-mule credential verification.

The primary contributions of this individual module the **Semantic Threat Intelligence and Mule Account Verification Engine** developed by **Liew Yi Ler** were detailed: fine-tuning a BERT deep learning model for phishing URL classification and corroborating it with multi-lingual scam signals, engineering an asynchronous SQLite 3NF mule registry with pre-compiled regex bytecode, and orchestrating these capabilities inside an asynchronous FastAPI microservice delivering a median verdict latency of 190 ms on the BERT path under a 50-user load.

Furthermore, the stakeholder benefit matrix, novel privacy advantages, project milestones, and the Hybrid Agile-MLOps engineering lifecycle were thoroughly delineated. This chapter establishes the rigorous foundation for **Chapter 2 (Literature Review)**, which examines existing machine learning phishing detection systems, natural language processing benchmarks, and architectural design patterns in contemporary cyber threat intelligence.
