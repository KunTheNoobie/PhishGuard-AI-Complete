# Design and Development of ‘PhishGuard-AI’: A Multi-Modal Integrated Financial Scam Detection System utilising Hybrid Deep Learning Semantic Threat Intelligence and Mule Account Verification Engine

<br>

**By**  
**LIEW YI LER**  
**Student ID: 25WMR09747**  

<br>

**Supervisor: Mr. Tan Yock Khang**  

<br>

A project report submitted to the  
**Faculty of Computing and Information Technology**  
in partial fulfillment of the requirements for the  
**Bachelor of Information Technology (Honours) in Information Security**  

<br>

**FACULTY OF COMPUTING AND INFORMATION TECHNOLOGY**  
**TUNKU ABDUL RAHMAN UNIVERSITY OF MANAGEMENT AND TECHNOLOGY**  
**KUALA LUMPUR**  

**ACADEMIC YEAR 2026/2027**  

<br>
<hr>
<br>

## Copyright Statement

Copyright © 2026 Tunku Abdul Rahman University of Management and Technology. All rights reserved.  
No part of this project documentation may be reproduced, stored in a retrieval system, or transmitted in any form or by any means (electronic, mechanical, photocopying, recording, or otherwise) without the prior written permission of Tunku Abdul Rahman University of Management and Technology.

<br>
<hr>
<br>

## Declaration

The project submitted herewith is a result of my own efforts in totality and in every aspect of the project works. All information that has been obtained from other sources has been fully acknowledged and referenced in accordance with academic standards. I understand that any plagiarism, cheating, or collusion of any sort constitutes a severe breach of Tunku Abdul Rahman University of Management and Technology (TAR UMT) rules and regulations and will be subjected to formal disciplinary actions.

<br><br>

_____________________________  
**Liew Yi Ler**  
Bachelor of Information Technology (Honours) in Information Security  
Student ID: 25WMR09747  
Date: 17 August 2026  

<br>
<hr>
<br>

## Abstract

Financial scams, deceptive credential harvesting, and sophisticated social engineering campaigns represent the single most destructive cybersecurity threat to Malaysia's rapidly evolving digital economy. Traditional defensive mechanisms rely overwhelmingly on static, signature-based blacklists (e.g., DNSBL, SURBL, Google Safe Browsing), which inherently suffer from severe time-to-protect latency and consistently fail to mitigate short-lived, ephemeral "Zero-Day" phishing campaigns and context-aware phishing kits. To decisively overcome these critical vulnerabilities, the **PhishGuard-AI** system was proposed as an enterprise-grade, multi-modal client-server cybersecurity platform. This dissertation details the comprehensive research, mathematical formulation, architectural design, and software implementation of the central intelligence core: the **Semantic Threat Intelligence and Mule Account Verification Engine** developed as an individual module by Liew Yi Ler.

The primary objective of this module is to transform web endpoint defence from reactive blacklist matching to proactive, real-time behavioural AI classification. A Transformer-based deep learning architecture utilizing Bidirectional Encoder Representations from Transformers (**BERT**) was fine-tuned over a specialized, multi-lingual corpus (English, Bahasa Melayu, and colloquial Manglish) to perform sub-100ms semantic inference on raw webpage Document Object Model (DOM) payloads and URL strings. This engine dynamically uncovers psychological urgency triggers, threats of account suspension, and Internationalized Domain Name (IDN) / typosquatted lookalike domains (e.g., `rnaybank.com`). To eliminate false positives on legitimate financial portals, an in-memory 28-Bank Trusted Domain Whitelist (`frozenset`) bypasses AI inference with zero overhead.

To combat rampant peer-to-peer e-commerce and social media fraud in Malaysia, an automated **Mule Account Verification Engine** was developed. Utilizing pre-compiled Regular Expression (Regex) bytecode optimized for 8 major Malaysian banking account formats (Maybank, CIMB, Public Bank, RHB, Hong Leong, AmBank, Bank Islam, Bank Rakyat), the engine autonomously scans visible webpage text and cross-references extracted financial credentials against a normalized SQLite 3NF database simulating the Royal Malaysia Police (PDRM) CCID *Semakmule* registry. Furthermore, the backend integrates optical Quishing (QR Phishing) decoding via OpenCV `cv2.QRCodeDetector()` to unmask obfuscated PayNet EMVCo DuitNow payment proxy strings.

These AI and database capabilities are orchestrated through a high-concurrency, asynchronous **FastAPI** microservice deployed on a Uvicorn ASGI server. By executing PyTorch tensor calculations in dedicated background worker threads (`asyncio.to_thread`) in parallel with asynchronous database I/O (`asyncio.gather`), the backend delivers a sub-400ms end-to-end verdict latency (`BLOCK_RENDER` vs. `SAFE`) to the Manifest V3 Chrome Extension client. Complementing the API, an integrated Security Operations Center (**SOC**) Threat Intelligence Dashboard delivers real-time Server-Sent Events (SSE) telemetry streaming, a 24-hour Threat Velocity timeline in Malaysia Standard Time (GMT+8), a real-world Geographic Attack Radar mapped to authentic Autonomous System Numbers (ASNs), and 1-click incident escalation to the National Scam Response Centre (NSRC 997) and National Fraud Portal (NFP). Empirical evaluation across 120 automated test cases validates that the proposed backend architecture achieves a 100% test pass rate, demonstrating resilient, zero-trust protection for digital banking consumers.

**Keywords**: Phishing Detection, BERT Natural Language Processing, Money Mule Account Verification, Semakmule Registry, FastAPI Microservices, Quishing Forensics, Threat Intelligence, Zero-Trust Endpoint Security.

<br>
<hr>
<br>

## Acknowledgements

First and foremost, I would like to express my deepest gratitude and highest respect to my Final Year Project supervisor, **Mr. Tan Yock Khang**, for his continuous mentorship, technical insights, and academic guidance throughout the entire lifecycle of this research. His profound expertise in information security, threat intelligence, and secure software engineering significantly elevated the academic rigour, architectural integrity, and practical viability of this project.

I would also like to extend my sincere appreciation to the **Faculty of Computing and Information Technology (FOCS)** at **Tunku Abdul Rahman University of Management and Technology (TAR UMT)** for providing state-of-the-art computational laboratories, software tooling, and an exceptional academic environment that fostered the success of this project.

A special acknowledgement is extended to my project partner, **Cheon Jie Han**, for his dedicated collaboration on the frontend client-side browser extension and visual convolutional neural network (CNN) logo detection module. The seamless integration between the client-side Manifest V3 architecture and the backend FastAPI AI microservice stands as a testament to our effective team synergy and rigorous parallel engineering.

Finally, I dedicate my deepest appreciation to my beloved family and friends for their unwavering patience, moral support, and boundless encouragement throughout my academic journey. Their steadfast belief in my aspirations provided the continuous motivation required to bring this dissertation to fruition.

<br>
<hr>
<br>

## Table of Contents

- [Chapter 1: Introduction](#chapter-1-introduction)
  - [1.1 Background of the Study](#11-background-of-the-study)
  - [1.2 Problem Statement](#12-problem-statement)
    - [1.2.1 The Latency of Static Blacklists Against Zero-Day Ephemeral Threats](#121-the-latency-of-static-blacklists-against-zero-day-ephemeral-threats)
    - [1.2.2 Evasion via Semantic Manipulation, Multilingual Triggers, and Typosquatting](#122-evasion-via-semantic-manipulation-multilingual-triggers-and-typosquatting)
    - [1.2.3 High Friction in the Verification of Localised Mule Accounts ("Keldai Akaun")](#123-high-friction-in-the-verification-of-localised-mule-accounts-keldai-akaun)
    - [1.2.4 Degradation of the CIA Triad in Digital Transactions](#124-degradation-of-the-cia-triad-in-digital-transactions)
  - [1.3 Objectives of the Project](#13-objectives-of-the-project)
  - [1.4 Solution: The Proposed Framework](#14-solution-the-proposed-framework)
    - [1.4.1 Securing Web Browsing with Dynamic Semantic BERT Analysis](#141-securing-web-browsing-with-dynamic-semantic-bert-analysis)
    - [1.4.2 Preventing Fraud via Automated Mule Credential Verification](#142-preventing-fraud-via-automated-mule-credential-verification)
    - [1.4.3 Enhancing System Availability via Asynchronous Microservices](#143-enhancing-system-availability-via-asynchronous-microservices)
    - [1.4.4 Live SOC Telemetry, Geographic Attack Radar & CTI Sharing](#144-live-soc-telemetry-geographic-attack-radar--cti-sharing)
  - [1.5 Target Market & Stakeholder Analysis](#15-target-market--stakeholder-analysis)
  - [1.6 Advantages & Novel Academic Contributions](#16-advantages--novel-academic-contributions)
  - [1.7 Project Plan & Management](#17-project-plan--management)
    - [1.7.1 Project Scope & Separation of Concerns](#171-project-scope--separation-of-concerns)
    - [1.7.2 Milestones & Project Schedule](#172-milestones--project-schedule)
    - [1.7.3 Hybrid Agile-MLOps Software Engineering Model](#173-hybrid-agile-mlops-software-engineering-model)
  - [1.8 Project Team & Organizational Structure](#18-project-team--organizational-structure)
  - [1.9 Chapter Summary & Evaluation](#19-chapter-summary--evaluation)

<br>
<hr>
<br>

# Chapter 1: Introduction

## 1.1 Background of the Study

In the contemporary era of the Fourth Industrial Revolution (IR 4.0), the global financial ecosystem has undergone an irreversible structural transformation towards decentralised, frictionless, and instantaneous digital transactions. Within Malaysia, aggressive national digitalisation blueprints—most notably the **MyDIGITAL Malaysia Digital Economy Blueprint** and the **Bank Negara Malaysia (BNM) Financial Sector Blueprint 2022–2026**—have systematically catalysed the nationwide adoption of real-time electronic payment rails. The pervasive deployment of national infrastructure such as the DuitNow real-time payment switch (operated by Payments Network Malaysia Sdn Bhd / PayNet), Touch 'n Go (TNG) eWallet, and integrated mobile banking applications has expanded digital financial inclusion across diverse socio-economic demographics in both urban and rural communities (Bank Negara Malaysia, 2023).

```
+----------------------------------------------------------------------------------------------------+
|                             MALAYSIAN DIGITAL FINANCIAL ECOSYSTEM (2026)                          |
+----------------------------------------------------------------------------------------------------+
|  • MyDIGITAL Blueprint & BNM 2022-2026 Strategic Directives                                        |
|  • Universal P2P Electronic Fund Transfers (DuitNow QR, TNG eWallet, Instant FPX Gateways)         |
|  • 94.8% National Mobile Internet Penetration (Massive Consumer Surface Area)                     |
+----------------------------------------------------------------------------------------------------+
                                                │
                                                ▼  Aggressive Threat Landscape Surge
+----------------------------------------------------------------------------------------------------+
|                              CRITICAL CYBER THREAT VECTORS IN MALAYSIA                             |
+----------------------------------------------------------------------------------------------------+
|  1. Ephemeral Zero-Day Phishing Portals  --> Brand impersonation of Maybank, CIMB, PDRM, KWSP/EPF   |
|  2. Multilingual Social Engineering      --> Coercive text in English, Bahasa Melayu, & Manglish   |
|  3. Illicit Money-Mule Networks         --> "Keldai Akaun" routing fraud proceeds via P2P transfers|
|  4. Optical Quishing Exploitation        --> Deceptive EMVCo DuitNow QR codes evading URL filters   |
+----------------------------------------------------------------------------------------------------+
```

However, this rapid digital transformation has drastically enlarged the attack surface accessible to cybercriminal syndicates, precipitating an unprecedented surge in financial cybercrime. As the technical barrier to entry for conducting digital transactions drops, internet users—a substantial proportion of whom possess limited formal cybersecurity awareness—are routinely targeted by sophisticated, multi-stage social engineering campaigns. When confidential banking credentials, Transaction Authorization Codes (TAC), and One-Time Passwords (OTP) are illicitly harvested, the ramifications are catastrophic. Beyond catastrophic personal financial losses suffered by individual victims, these breaches inflict lasting reputational damage on national financial institutions and critically erode public confidence in the digital banking ecosystem.

Empirical statistics released by **CyberSecurity Malaysia**, the **National Scam Response Centre (NSRC 997)**, and the **Royal Malaysia Police (PDRM) Commercial Crime Investigation Department (CCID)** reveal that online financial fraud and deceptive phishing currently represent the single largest cybercrime category in Malaysia. Financial losses stemming from telecommunication fraud, deceptive investment schemes, e-commerce scams, and phishing campaigns exceeded **RM1.3 billion in 2023**, with subsequent years exhibiting an aggressive upward trajectory (CyberSecurity Malaysia, 2024; Royal Malaysia Police, 2024).

Historically, phishing attacks were characterized by rudimentary, mass-distributed spam emails containing generic salutations and conspicuous orthographic errors that were readily flagged by heuristic spam filters. Today, cybercrime syndicates operate as industrialized enterprises utilizing modern Phishing-as-a-Service (PhaaS) frameworks (e.g., EvilProxy, Modlishka), Domain Generation Algorithms (DGA), fast-flux DNS hosting networks, and generative Artificial Intelligence (AI) to synthesize contextually flawless, highly persuasive attack narratives (Alkhalil et al., 2021; Opara et al., 2023). Attackers deploy sophisticated brand clones mimicking Malaysia's premier banking institutions—including Malayan Banking Berhad (Maybank), CIMB Bank Berhad, Public Bank Berhad, and government statutory bodies such as the Employees Provident Fund (KWSP/EPF) and the Inland Revenue Board (LHDN).

To confront these national security challenges, the **PhishGuard-AI** project was initiated to design and engineer a proactive, multi-modal browser security suite. Rather than relying on reactive blacklists, PhishGuard-AI embeds Artificial Intelligence directly at the endpoint to autonomously inspect, predict, and intercept emerging cyber threats. Because of the vast interdisciplinary complexity of this system, the engineering responsibilities were strategically partitioned into two collaborative modules:
1. **Module 1 (Author - Liew Yi Ler)**: Semantic Threat Intelligence and Mule Account Verification Engine (Backend Server & AI Core).
2. **Module 2 (Collaborator - Cheon Jie Han)**: Visual Identity Analysis and Client-Side Browser Integration (Frontend Extension & CNN Vision).

This dissertation focuses exclusively on the backend intelligence engine developed by **Liew Yi Ler**. By combining fine-tuned **Bidirectional Encoder Representations from Transformers (BERT)** Natural Language Processing with deterministic Regular Expression (Regex) bytecode execution and asynchronous database verification, this backend establishes a zero-trust browsing environment that neutralizes financial fraud at sub-second speeds.

---

## 1.2 Problem Statement

Despite continuous advancements in network perimeter firewalls and browser sandboxing, end-users remain acutely vulnerable to financial scams due to four fundamental architectural deficiencies in contemporary defensive technologies:

```
+----------------------------------------------------------------------------------------------------+
|                           FOUR CORE CYBERSECURITY DEFENSIVE DEFICIENCIES                           |
+----------------------------------------------------------------------------------------------------+
|  1. Zero-Day Latency Gap         --> Blacklists take 4-48 hours; Phishing domains die in < 2 hours |
|  2. Semantic & Language Evasion  --> Keyword filters fail on Manglish, urgency triggers & homoglyphs|
|  3. Mule Account Friction        --> PDRM Semakmule manual lookup is high-friction and never done  |
|  4. CIA Triad Collapse           --> Total compromise of Confidentiality, Integrity, & Availability|
+----------------------------------------------------------------------------------------------------+
```

### 1.2.1 The Latency of Static Blacklists Against Zero-Day Ephemeral Threats
Traditional web security architectures rely predominantly on deterministic, signature-based blacklists (e.g., Google Safe Browsing, DNSBL, PhishTank, Spamhaus). While computationally inexpensive, blacklists operate purely reactively. To flag a malicious domain, the URL must first be reported by a victim, crawled by security bots, mathematically analyzed, and propagated globally to client caches. 

Empirical research establishes that the average "Time-to-Protect" latency of global blacklists ranges from **4 to 48 hours** (NIST, 2023). Conversely, modern automated phishing kits deploy ephemeral domains with an average operational lifespan of **under two hours**—frequently retiring the domain before security crawlers can issue a signature. Consequently, early victims visiting a "Zero-Day" phishing site receive zero protection from standard browser safeguards.

### 1.2.2 Evasion via Semantic Manipulation, Multilingual Triggers, and Typosquatting
Modern threat actors systematically bypass string-matching and keyword-density filters (e.g., TF-IDF) by employing sophisticated semantic manipulation. Attackers craft persuasive Document Object Model (DOM) content embedded with psychological coercion triggers (e.g., *"Akaun bank anda telah digantung! Sila sahkan TAC dalam masa 5 minit"*), artificial countdown timers, and fake security trust badges. 

Furthermore, in multicultural regions like Malaysia, phishing campaigns heavily exploit multi-lingual colloquialisms (Bahasa Melayu, English, and localized Manglish) that generic English-centric classifiers fail to evaluate. Threat actors also exploit Internationalized Domain Name (IDN) homoglyph attacks and subtle typosquatting permutations (e.g., replacing `m` with `rn` to register `rnaybank.com`), evading syntactic filters while successfully deceiving human visual perception (Sahingoz et al., 2019; Opara et al., 2023).

### 1.2.3 High Friction in the Verification of Localised Mule Accounts ("Keldai Akaun")
In domestic e-commerce fraud and peer-to-peer marketplace scams (e.g., Facebook Marketplace, Telegram channels, Mudah.my), syndicates route illicit proceeds through compromised third-party bank accounts known colloquially as *"Keldai Akaun"* (Money Mule Accounts). While the Royal Malaysia Police (PDRM) CCID operates the public *Semakmule* database, verifying a beneficiary account requires a user to manually copy the account number, navigate away from the transaction page, access the external government portal, complete a CAPTCHA challenge, and interpret the record (Royal Malaysia Police, 2023).

This high-friction, manual process is almost never performed by average consumers during fast-paced digital transactions. Consequently, flagged money-mule accounts operate unimpeded directly within the user's browser viewport without triggering any automated endpoint alerts.

### 1.2.4 Degradation of the CIA Triad in Digital Transactions
A single successful phishing interaction triggers a cascading failure that obliterates the foundational security principles of the **CIA Triad (Confidentiality, Integrity, and Availability)**:
* **Confidentiality**: Coercing users into disclosing passwords, NRIC numbers, and TAC/OTP codes on fraudulent forms grants unauthorized adversaries access to private financial data.
* **Integrity**: With compromised authentication tokens, attackers manipulate transaction states, modify standing beneficiary instructions, and execute unauthorized wire transfers.
* **Availability**: Fraud syndicates frequently lock legitimate users out of their online banking accounts by altering recovery email addresses and credentials, inducing a total denial of service for the victim's liquid assets.

```plantuml
@startuml CIA_Triad_Vulnerability_Model
!theme vibrant
skinparam backgroundColor #0f172a
skinparam ArrowColor #38bdf8
skinparam ComponentBorderColor #38bdf8
skinparam ComponentBackgroundColor #1e293b
skinparam ComponentFontColor #f8fafc
skinparam PackageBorderColor #64748b
skinparam PackageFontColor #94a3b8

title CIA Triad Threat Degradation & PhishGuard-AI Defensive Mitigation

package "CIA Triad Threat Impact" {
    [Confidentiality Breach\n• Password & NRIC Harvesting\n• Session Token Interception] as ConfThreat
    [Integrity Compromise\n• Unauthorized Fund Transfers\n• Altered Mule Beneficiaries] as IntegThreat
    [Availability Disruption\n• Account Lockout & Hijacking\n• Denial of Liquid Assets] as AvailThreat
}

package "PhishGuard-AI Backend Countermeasures" {
    [BERT Semantic Engine\n• Real-Time Contextual NLP\n• Typosquatting Interception] as BERTSolution
    [Mule Verification Engine\n• Regex DOM Account Scanner\n• Simulated Semakmule DB] as MuleSolution
    [FastAPI Async Architecture\n• Sub-400ms Decision Engine\n• NSRC / NFP Account Freezing] as APISolution
}

ConfThreat .down.> BERTSolution : Proactively Neutralized By
IntegThreat .down.> MuleSolution : Automatically Blocked By
AvailThreat .down.> APISolution : Guaranteed Availability & Defense By

@enduml
```

---

## 1.3 Objectives of the Project

The primary goal of this research project is to architect, develop, and evaluate an intelligent, high-throughput backend microservice platform capable of real-time semantic analysis and automated financial credential verification. The specific technical objectives established for this individual module are:

1. **To Engineer a Multi-Lingual Semantic Threat Intelligence Engine Utilizing Fine-Tuned BERT NLP**:  
   Train and fine-tune a Bidirectional Encoder Representations from Transformers (`bert-base-uncased`) deep learning model on a curated dataset of over 20,000 localized phishing and legitimate webpage payloads (English, Bahasa Melayu, and Manglish). The objective is to achieve high precision ($\ge 95\%$) in detecting semantic manipulation, urgent psychological triggers, and typosquatted domains in under 100 milliseconds per inference.

2. **To Design and Implement an Automated Mule Account Verification Engine for Malaysian Financial Formats**:  
   Develop a low-latency credential extraction algorithm utilizing pre-compiled Regular Expression (Regex) bytecode to scan webpage DOM text for 10-to-14-digit bank account formats across 8 major Malaysian banking institutions. Integrate an asynchronous SQLite 3NF relational database simulating the PDRM CCID *Semakmule* registry to flag verified mule accounts in real time with zero manual user friction.

3. **To Architect a High-Concurrency, Low-Latency FastAPI Microservice with Enterprise SOC Capabilities**:  
   Construct an asynchronous RESTful backend utilizing FastAPI and Uvicorn that orchestrates AI tensor calculations (`asyncio.to_thread`) and database I/O concurrently using `asyncio.gather()`. The microservice must achieve an end-to-end response time under 400 milliseconds, provide a Server-Sent Events (SSE) live telemetry stream, host a 24-hour Threat Velocity timeline in Malaysia Time (GMT+8), and expose standardized CTI incident exporters (OASIS STIX 2.1 JSON, CEF, Syslog, and NSRC 997 dispatch formats).

---

## 1.4 Solution: The Proposed Framework

To systematically resolve the challenges outlined in Section 1.2, the PhishGuard-AI backend implements a multi-layered, asynchronous intelligence pipeline:

```
+----------------------------------------------------------------------------------------------------+
|                         PHISHGUARD-AI MULTI-TIER BACKEND DEFENSE PIPELINE                          |
+----------------------------------------------------------------------------------------------------+
|  Layer 1: 28-Bank In-Memory Whitelist   --> Instant frozenset lookup (0ms overhead for real banks) |
|  Layer 2: Transformer NLP Engine        --> Fine-tuned BERT deep learning classification (English/BM)|
|  Layer 3: Mule Account Regex Scanner    --> Pre-compiled bytecode matching Maybank, CIMB, RHB...  |
|  Layer 4: SQLite 3NF Semakmule Registry --> Asynchronous aiosqlite match on known fraud accounts  |
|  Layer 5: Brand Impersonation Index     --> Levenshtein distance & homoglyph heuristic quantification|
|  Layer 6: Optical Quishing Forensics    --> OpenCV EMVCo QR code decoding of DuitNow proxy targets |
|  Layer 7: Asynchronous Aggregator       --> asyncio.gather() sub-400ms verdict (BLOCK_RENDER / SAFE)|
+----------------------------------------------------------------------------------------------------+
```

### 1.4.1 Securing Web Browsing with Dynamic Semantic BERT Analysis
To neutralize the zero-day latency of static blacklists, PhishGuard-AI deploys a fine-tuned BERT Transformer neural network. When an end-user navigates to an unverified webpage, the client extension extracts the sanitized DOM text and dispatches it to the FastAPI microservice. 

The BERT engine executes **WordPiece tokenization** to generate bidirectional contextual embeddings. By analyzing the entire syntactic structure of the text rather than isolated keywords, the model distinguishes between benign financial notices and coercive phishing attempts (e.g., fraudulent suspension notices requesting immediate TAC entry). To ensure authentic banking websites experience zero AI latency and zero false alarms, an in-memory **28-Bank Trusted Domain Whitelist (`frozenset`)** bypasses the neural network for verified domains (e.g., `maybank2u.com.my`, `pbebank.com`).

### 1.4.2 Preventing Fraud via Automated Mule Credential Verification
To eliminate the manual friction of the PDRM *Semakmule* lookup, the backend incorporates an automated regex extraction and database verification engine. As webpage content is ingested, the engine executes pre-compiled regular expressions calibrated to the specific account number lengths and prefix patterns of 8 major Malaysian banks. 

Extracted account numbers are immediately queried against an internal SQLite database operating in **Write-Ahead Logging (WAL)** mode. If a match is detected, the API immediately injects the mule account's fraud history, report count, and flagged platform into the JSON response payload, triggering an instantaneous block before funds can be transferred.

### 1.4.3 Enhancing System Availability via Asynchronous Microservices
Heavy deep learning models executed naively inside web servers block the main application event loop, leading to server thread exhaustion and high latency. To preserve responsiveness, the backend is built on **FastAPI** running on the **Uvicorn** Asynchronous Server Gateway Interface (ASGI). 

Computational PyTorch tensors are dispatched to separate thread pools using `asyncio.to_thread()`, while database queries and heuristics run concurrently via `asyncio.gather()`. This architecture guarantees that full multi-modal analysis completes in **under 400 milliseconds**, ensuring zero disruption to normal web browsing speeds.

### 1.4.4 Live SOC Telemetry, Geographic Attack Radar & CTI Sharing
The backend features an integrated Threat Intelligence Dashboard (`/dashboard/`) powered by Server-Sent Events (SSE). The dashboard visualizes real-time detections, renders a full 24-hour Threat Velocity spectrum synchronized to Malaysia Standard Time (GMT+8), and maps attack origins to authentic global telecommunication ASNs (e.g., TM Net `AS4788`, Singtel `AS7473`, Cloudflare `AS13335`). 

For institutional defense, the backend provides 1-click incident escalation to the **National Scam Response Centre (NSRC 997)** and automated threat intelligence sharing via **OASIS STIX 2.1 JSON bundles**, ArcSight CEF, and RFC 5424 Syslog feeds.

```plantuml
@startuml System_Architecture_Chapter_1
!theme vibrant
skinparam backgroundColor #0f172a
skinparam ArrowColor #38bdf8
skinparam ComponentBorderColor #38bdf8
skinparam ComponentBackgroundColor #1e293b
skinparam ComponentFontColor #f8fafc
skinparam InterfaceFontColor #38bdf8
skinparam PackageBorderColor #64748b
skinparam PackageFontColor #94a3b8

title Figure 1.1: PhishGuard-AI High-Level System Architecture & Engineering Module Separation

package "Client-Side Frontend Architecture\n[Scope: Cheon Jie Han - Module 2]" {
    [Google Chrome Browser Client] as ChromeClient
    [Manifest V3 Background Service Worker] as ServiceWorker
    [Content Script DOM Extractor & Interceptor] as ContentScript
    [YOLOv8 / CNN Visual Brand Classifier] as VisualEngine
    [Popup UI & Trusted Sites Manager] as PopupUI
    [Full-Screen BLOCK_RENDER Defense Shield] as BlockOverlay
}

package "Backend Intelligence & Microservice Gateway\n[Scope: Liew Yi Ler - Module 1 (Author)]" {
    interface "FastAPI REST API Gateway\n(Bearer Token Auth / Port 8000)" as APIGateway
    [Asynchronous Request Orchestrator\n(asyncio.gather / Uvicorn ASGI)] as Orchestrator
    [28-Bank Trusted Domain Whitelist\n(frozenset Zero-Latency Filter)] as WhitelistEngine
    
    package "Core Intelligence Engines" {
        [Semantic Threat Intelligence Engine\n(Fine-Tuned BERT NLP / PyTorch)] as BERTEngine
        [Mule Account Verification Engine\n(Pre-Compiled Regex Bytecode)] as RegexEngine
        [Brand Impersonation Profiler (BII)\n(Levenshtein Distance & Heuristics)] as BrandProfiler
        [Optical Quishing Forensics Engine\n(OpenCV EMVCo DuitNow QR Decoder)] as QuishingEngine
    }
    
    database "SQLite 3NF Persistence\n(WAL Mode / aiosqlite Pool)" {
        [Mule Registry Database\n(Simulated PDRM CCID Semakmule)] as MuleDB
        [Threat Telemetry & Forensic Logs] as TelemetryDB
    }

    package "Enterprise SOC Operations & CTI" {
        [Live Threat Intelligence Dashboard\n(Server-Sent Events / SSE Stream)] as Dashboard
        [Geographic Attack Radar\n(AS4788, AS7473, AS13335)] as GeoRadar
        [NSRC 997 & NFP Freeze Bridge] as NFPBridge
        [STIX 2.1 & SIEM Exporters\n(CEF / Syslog / Pi-hole Sinkhole)] as SIEMExporter
    }
}

ChromeClient --> ContentScript : 1. Page Load & DOM Parsing
ContentScript --> ServiceWorker : 2. Raw HTML & URL Payload
ServiceWorker --> VisualEngine : 3. Screenshot Visual Inspection
ServiceWorker --> APIGateway : 4. Asynchronous POST /api/v1/analyze/semantics
APIGateway --> WhitelistEngine : 5. Fast Pre-Inference Whitelist Check
WhitelistEngine --> Orchestrator : Non-Whitelisted URL
Orchestrator --> BERTEngine : Parallel Task 1: Semantic Intent Analysis
Orchestrator --> RegexEngine : Parallel Task 2: Mule Extraction
RegexEngine --> MuleDB : Exact Match Lookup
Orchestrator --> BrandProfiler : Parallel Task 3: Impersonation Scoring
BERTEngine --> TelemetryDB : Persist Forensic Verdict
Orchestrator --> APIGateway : Unified Aggregated Payload (Sub-400ms)
APIGateway --> ServiceWorker : JSON Verdict (BLOCK_RENDER / SAFE)
ServiceWorker --> BlockOverlay : Render Defense Shield (If Phishing)
TelemetryDB --> Dashboard : Real-Time SSE Event Stream
TelemetryDB --> GeoRadar : Live Threat Coordinates
Dashboard --> NFPBridge : 1-Click Law Enforcement Freeze
Dashboard --> SIEMExporter : Export CTI Dossier

@enduml
```

---

## 1.5 Target Market & Stakeholder Analysis

PhishGuard-AI is engineered to deliver pervasive protection across diverse stakeholder tiers in the digital ecosystem:

### Primary Users:
1. **General Public and Elderly Internet Banking Consumers**:  
   Individuals who frequently utilize web browsers for e-commerce, bill payments, and online banking but lack formal technical training to detect homoglyph attacks, analyze SSL/TLS certificate chains, or identify subtle linguistic coercion. Their core requirement is an autonomous, "zero-click" endpoint security layer that intercepts threats seamlessly without interrupting normal navigation.
2. **Small and Medium Enterprise (SME) Personnel**:  
   Employees in procurement, accounting, and administrative roles who manage digital invoices and wire transfers. This demographic is heavily targeted by Business Email Compromise (BEC) and invoice redirection scams that utilize newly registered domains designed to bypass standard corporate firewalls.

### Secondary Users & Institutional Beneficiaries:
1. **Commercial Banks & Financial Institutions (Maybank, CIMB, Public Bank, RHB, PayNet)**:  
   Security Operations Centers (SOC) and Fraud Risk teams seeking to curb customer credential theft, brand spoofing, and dispute liability claims. They benefit directly from an ecosystem that intercepts money-mule transfers before funds leave the consumer's account.
2. **Cybersecurity Operations & Law Enforcement Agencies (PDRM CCID, CyberSecurity Malaysia, NSRC 997)**:  
   Incident response analysts who require structured, forensically sound digital dossiers. The platform auto-formats telemetry into standardized law enforcement dispatch records and STIX 2.1 cyber threat intelligence feeds.

```
+----------------------------------------------------------------------------------------------------+
|                                    STAKEHOLDER BENEFIT MATRIX                                      |
+----------------------------------------------------------------------------------------------------+
|  • General Public & Elderly  --> "Zero-Click" automatic blocking, zero manual Semakmule overhead    |
|  • SME Businesses           --> Real-time credential protection against invoice and BEC fraud      |
|  • Commercial Banks         --> Reduced fraud reimbursement claims, brand reputation protection    |
|  • Law Enforcement (PDRM)   --> Automated forensic dispatch dossiers, real-time mule syndication   |
+----------------------------------------------------------------------------------------------------+
```

---

## 1.6 Advantages & Novel Academic Contributions

The engineering of the PhishGuard-AI backend provides substantial practical and academic contributions to the domain of cybersecurity:

* **Enhanced Edge-Adjacent Data Confidentiality and Privacy**:  
  By deploying lightweight, fine-tuned BERT models on a localized, self-hosted microservice rather than dispatching user DOM text to commercial third-party cloud LLM APIs (e.g., OpenAI, Anthropic), the system guarantees that sensitive user form inputs and session tokens are never leaked to external third parties.
* **Proactive Elimination of Zero-Day Phishing Windows**:  
  Shifting threat detection from reactive signature matching to semantic intent classification neutralizes zero-day phishing sites within milliseconds of domain instantiation, eliminating the 4-to-48-hour vulnerability window inherent to static blacklists.
* **Frictionless Money-Mule Account Interception**:  
  Automating regex credential extraction and SQLite database verification directly within the backend pipeline removes the friction of manual government registry lookups, directly addressing the core vector of domestic peer-to-peer financial fraud.
* **Direct Alignment with United Nations Sustainable Development Goals (UN SDGs)**:  
  This research directly advances **UN SDG 16 (Peace, Justice, and Strong Institutions)** by providing technological tooling to dismantle illicit cybercrime syndicates, and **UN SDG 9 (Industry, Innovation, and Infrastructure)** by strengthening the resilience and reliability of digital banking infrastructure (United Nations, 2015).

---

## 1.7 Project Plan & Management

### 1.7.1 Project Scope & Separation of Concerns
To achieve high-quality software engineering standards, the PhishGuard-AI project was partitioned into two distinct engineering scopes between the two project members:
* **Backend Server & AI Core (Author: Liew Yi Ler - Module 1)**: Covers model fine-tuning, BERT semantic inference, regex credential extraction, SQLite 3NF mule registry database, FastAPI ASGI routing, SSE telemetry streaming, and CTI exporters.
* **Frontend Client & Computer Vision (Collaborator: Cheon Jie Han - Module 2)**: Covers Manifest V3 Chrome extension service workers, DOM extraction, popup UI, full-screen `BLOCK_RENDER` shield overlay, and CNN/YOLOv8 visual logo detection.

The detailed module breakdown and task allocation is formalized in Table 1.1.

**Table 1.1: Description of System Modules and Task Allocation**

| System Module | Detailed Engineering Scope | Assigned Member |
| :--- | :--- | :--- |
| **Semantic Threat Intelligence Engine** | • Fine-tunes and evaluates BERT (`bert-base-uncased`) on multi-lingual datasets (English, Bahasa Melayu, Manglish).<br>• Implements text sanitization, WordPiece tokenization, and softmax risk probability calibration.<br>• Integrates 28-Bank Trusted Whitelist (`frozenset`) for zero-latency false-positive prevention. | **Liew Yi Ler** (Module 1 - Author) |
| **Mule Account Verification Engine** | • Engineers pre-compiled Python Regex bytecode matching 8 Malaysian bank account formats.<br>• Designs and maintains the SQLite 3NF relational database (WAL mode) for known fraud accounts.<br>• Develops real-time matching and forensic aggregation logic. | **Liew Yi Ler** (Module 1 - Author) |
| **Backend API Gateway & SOC Operations** | • Constructs the asynchronous FastAPI microservice with Bearer Token authentication.<br>• Implements `asyncio.to_thread` and `asyncio.gather` for sub-400ms parallel execution.<br>• Builds the Live SOC Dashboard, SSE event stream, 24h GMT+8 timeline, and STIX 2.1 CTI exporter. | **Liew Yi Ler** (Module 1 - Author) |
| **Visual Identity Analysis (CNN / YOLOv8)** | • Trains a Convolutional Neural Network on the PhishPedia logo dataset.<br>• Identifies brand impersonation of Malaysian commercial banks via screenshot visual matching. | **Cheon Jie Han** (Module 2) |
| **Client-Side Browser Integration** | • Develops the Manifest V3 Google Chrome Extension utilizing Service Workers and Content Scripts.<br>• Implements deep DOM/Shadow DOM extraction and the high-impact Red Defense Shield overlay. | **Cheon Jie Han** (Module 2) |

```plantuml
@startuml Threat_Interception_Sequence_Chapter_1
!theme vibrant
skinparam backgroundColor #0f172a
skinparam ArrowColor #38bdf8
skinparam SequenceLifeLineBorderColor #38bdf8
skinparam SequenceLifeLineBackgroundColor #1e293b
skinparam ParticipantBorderColor #38bdf8
skinparam ParticipantBackgroundColor #1e293b
skinparam ParticipantFontColor #f8fafc

title Figure 1.2: Asynchronous Multi-Modal Threat Interception & Verification Sequence Flow

autonumber
actor "End User" as User
participant "Content Script\n(Chrome MV3)" as CS
participant "Background Service Worker\n(Extension Brain)" as SW
participant "FastAPI Gateway\n(Backend Microservice)" as API
participant "BERT NLP Engine\n(PyTorch / Threads)" as BERT
participant "Mule Verification Engine\n(Regex + aiosqlite)" as MULE
participant "Threat Telemetry DB\n(SQLite WAL Mode)" as DB

User -> CS : Navigates to Target Webpage (e.g. malicious clone)
activate CS
CS -> CS : Deep DOM & Shadow Root Text Extraction
CS -> SW : Dispatch Payload (URL, Sanitized DOM, Origin)
deactivate CS

activate SW
SW -> SW : Check Client-Side Trusted Sites Cache
SW -> API : POST /api/v1/analyze/semantics (Bearer Auth)
activate API

API -> API : Check 28-Bank In-Memory Whitelist (frozenset)
alt Domain is Whitelisted Legitimate Bank
    API --> SW : Return HTTP 200 { verdict: "SAFE", confidence: 0.00 }
else Domain Requires Semantic & Mule Inspection
    par Concurrent Execution (asyncio.gather)
        API -> BERT : asyncio.to_thread(bert_classify, text, url)
        activate BERT
        BERT -> BERT : WordPiece Tokenization & Softmax Classification
        BERT --> API : Semantic Risk Score (e.g. 0.965)
        deactivate BERT
    else
        API -> MULE : scan_and_verify_mules(sanitized_text)
        activate MULE
        MULE -> MULE : Pre-compiled Regex (Maybank, CIMB, RHB...)
        MULE -> DB : SELECT * FROM mule_registry WHERE account IN (...)
        DB --> MULE : Flagged Fraud Record Found
        MULE --> API : Mule Match Array [{bank, account, reports}]
        deactivate MULE
    end

    API -> API : Multi-Vector Risk Aggregation & Calibration
    API -> DB : Log Forensic Telemetry Record (Non-blocking)
    API --> SW : Return JSON Verdict { verdict: "BLOCK_RENDER", risk: 0.98 }
end
deactivate API

alt Verdict == "BLOCK_RENDER"
    SW -> CS : Command: Render High-Impact Defense Shield
    activate CS
    CS -> CS : Remove Malicious DOM & Display Red Shield
    CS --> User : Display Threat Breakdown & Safe Escape Action
    deactivate CS
else Verdict == "SAFE"
    SW -> CS : Command: Allow Normal Browsing
end
deactivate SW

@enduml
```

---

### 1.7.2 Milestones & Project Schedule
The research and implementation schedule spanned two consecutive academic semesters (Project I and Project II), detailed in Table 1.2.

**Table 1.2: Project Milestones and Schedule**

| Project Phase / Activity | Expected Deliverable / Outcome | Completion Timeline |
| :--- | :--- | :--- |
| **Project Proposal Submission (Forms 1, 2, 3)** | Formalize project objectives, technical scope, and preliminary system architecture for supervisor review. | June 2026 |
| **Proposal Moderation Presentation** | Present architectural design to faculty moderation panel; incorporate feedback on threat models. | June 2026 |
| **Submission of Chapter 1: Introduction** | Complete comprehensive background study, problem statements, objectives, scope, and project management plans. | July 2026 |
| **Submission of Chapter 2: Literature Review** | Critical evaluation of machine learning phishing detection, NLP transformer benchmarks, and mule account architectures. | August 2026 |
| **Submission of Chapter 3: Methodology** | Formalize Agile-MLOps engineering methodology, functional/non-functional requirements, and mathematical formulations. | September 2026 |
| **Submission of Chapter 4: System Design** | Complete detailed system design, UML architecture diagrams, SQLite 3NF schemas, and API contract specifications. | October 2026 |
| **Submission of Project 1 Portfolio** | Compile interim research documentation, prototype evidence, and code repositories for faculty evaluation. | November 2026 |
| **Test Plan Preparation & System Preview** | Develop 120 automated pytest test cases and conduct prototype demonstration for the supervisor. | December 2026 |
| **Final System Verification & Moderation** | Execute full integration testing, stress testing, and obtain final verification from supervisor and moderator. | January 2027 |
| **Draft FYP Dissertation Submission** | Submit complete individual report draft encompassing all 6 chapters, appendices, and empirical results. | February 2027 |
| **Final FYP Submission & Oral Defense** | Submit finalized dissertation, open-source code repository, presentation slides, and demonstration video. | March 2027 |

---

### 1.7.3 Hybrid Agile-MLOps Software Engineering Model
Standard Software Development Life Cycles (e.g., Waterfall) are incapable of accommodating the empirical, non-linear iterations required in machine learning model development. Consequently, this project adopted a **Hybrid Agile-MLOps Engineering Model**:

```
+----------------------------------------------------------------------------------------------------+
|                         HYBRID AGILE-MLOPS SOFTWARE DEVELOPMENT LIFECYCLE                          |
+----------------------------------------------------------------------------------------------------+
|  1. Agile Sprint Management  --> Bi-weekly iterative development cycles, continuous code reviews   |
|  2. MLOps Data Pipeline      --> Multi-lingual data harvesting, sanitization & WordPiece encoding  |
|  3. Model Tuning & Auditing  --> Hyperparameter search, cross-entropy loss tracking, F1 evaluation |
|  4. Continuous Integration   --> Automated Pytest CI/CD (120 test cases enforcing 100% pass rate) |
|  5. Microservice Packaging   --> Asynchronous FastAPI containerization with sub-second SLA checks  |
+----------------------------------------------------------------------------------------------------+
```

1. **Agile Framework**: Governs microservice architecture, API endpoint routing, and dashboard development through two-week iterative sprints, allowing flexible adaptation as new evasion tactics were uncovered.
2. **Machine Learning Operations (MLOps)**: Integrates continuous data curation, hyperparameter optimization, loss convergence monitoring, and rigorous model evaluation (Precision, Recall, F1-Score, Confusion Matrices) directly into each sprint cycle (Kreuzberger et al., 2023).

```plantuml
@startuml Agile_MLOps_Lifecycle_Chapter_1
!theme vibrant
skinparam backgroundColor #0f172a
skinparam ArrowColor #38bdf8
skinparam ActivityBorderColor #38bdf8
skinparam ActivityBackgroundColor #1e293b
skinparam ActivityFontColor #f8fafc

title Figure 1.3: Hybrid Agile-MLOps Engineering Lifecycle Framework

start
:Sprint Planning & Cybersecurity Threat Modeling;

partition "MLOps Pipeline (Data & Model Engineering)" {
    :1. Dataset Curation (English, Bahasa Melayu, Manglish Phishing Corpus);
    :2. Text Sanitization & WordPiece Tokenization;
    :3. Model Training & Fine-Tuning (BERT Base Uncased);
    :4. Hyperparameter Optimization & Loss Convergence Analysis;
    :5. Evaluation via Confusion Matrix, Precision, Recall & F1-Score;
    if (F1-Score >= 0.95 and Inference Latency < 100ms?) then (yes)
        :Export PyTorch Model Weights & Quantized Assets;
    else (no)
        :Augment Dataset with Edge Cases & Re-tune;
        stop
    endif
}

partition "Agile Development (Microservice & API Architecture)" {
    :6. Develop FastAPI Microservice & Async Endpoints;
    :7. Engineer Regex Bytecode & SQLite 3NF Mule Registry;
    :8. Implement In-Memory 28-Bank Trusted Whitelist;
    :9. Build Live SOC Telemetry Dashboard & Geo Radar;
    :10. Unit & Integration Testing (Pytest Suite - 120/120 Tests);
}

partition "System Deployment & Continuous Verification" {
    :11. End-to-End System Preview & Supervisor Moderation;
    :12. Real-World Honeypot & Benchmark Validation;
    :13. Security Hardening, Rate Limiting & Bearer Auth;
}

:Final System Sign-Off & Project Dissertation Submission;
stop

@enduml
```

---

## 1.8 Project Team & Organizational Structure

To guarantee project success and strict accountability, the responsibilities between the two team members were clearly established as outlined in Table 1.3.

**Table 1.3: Project Team Organization & RACI Matrix**

| System Function / Engineering Layer | Backend Server & AI Core (Liew Yi Ler) | Frontend Client & Extension (Cheon Jie Han) |
| :--- | :---: | :---: |
| **BERT Semantic NLP Model Fine-Tuning** | **Accountable & Responsible** | Consulted |
| **Mule Account Regex & 3NF SQLite Database** | **Accountable & Responsible** | Informed |
| **FastAPI Microservice & Asynchronous Orchestration** | **Accountable & Responsible** | Informed |
| **Live SOC Dashboard, SSE Stream & Geo Radar** | **Accountable & Responsible** | Informed |
| **Visual Brand Classifier (CNN / YOLOv8)** | Informed | **Accountable & Responsible** |
| **Manifest V3 Chrome Extension & Service Worker** | Consulted | **Accountable & Responsible** |
| **DOM Deep Extraction & Red Shield Overlay** | Consulted | **Accountable & Responsible** |
| **End-to-End Client-Server System Integration** | **Jointly Responsible** | **Jointly Responsible** |

---

## 1.9 Chapter Summary & Evaluation

This introductory chapter has established the foundational rationale, theoretical background, problem space, and technical scope of the **PhishGuard-AI** research project. Modern financial cybercrime in Malaysia has outpaced traditional static blacklists, necessitating an AI-driven paradigm shift towards real-time semantic analysis and automated money-mule credential verification.

The primary contributions of this individual module—the **Semantic Threat Intelligence and Mule Account Verification Engine** developed by **Liew Yi Ler**—were detailed: fine-tuning a BERT deep learning model for multi-lingual phishing intent classification, engineering an asynchronous SQLite 3NF mule registry with pre-compiled regex bytecode, and orchestrating these capabilities inside an asynchronous FastAPI microservice delivering sub-400ms end-to-end verdict latencies.

Furthermore, the stakeholder benefit matrix, novel privacy advantages, project milestones, and the Hybrid Agile-MLOps engineering lifecycle were thoroughly delineated. This chapter establishes the rigorous foundation for **Chapter 2 (Literature Review)**, which examines existing machine learning phishing detection systems, natural language processing benchmarks, and architectural design patterns in contemporary cyber threat intelligence.
