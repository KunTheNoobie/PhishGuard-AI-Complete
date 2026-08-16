# Design and Development of ‘PhishGuard-AI’: A Multi-Modal Integrated Financial Scam Detection System utilising Hybrid Deep Learning Semantic Threat Intelligence and Mule Account Verification Engine

**By**  
**Liew Yi Ler**

**FACULTY OF COMPUTING AND INFORMATION TECHNOLOGY**  
**TUNKU ABDUL RAHMAN UNIVERSITY OF MANAGEMENT AND TECHNOLOGY**  
**KUALA LUMPUR**

**ACADEMIC YEAR 2026/2027**

---

# Design and Development of ‘PhishGuard-AI’: A Multi-Modal Integrated Financial Scam Detection System utilising Hybrid Deep Learning Semantic Threat Intelligence and Mule Account Verification Engine

**By**  
**Liew Yi Ler**

**Supervisor: Mr. Tan Yock Khang**

A project report submitted to the  
Faculty of Computing and Information Technology  
in partial fulfillment of the requirement for the  
**Bachelor of Information Technology (Honours) in Information Security**

**Academic Year 2026/2027**

**Faculty of Computing and Information Technology**  
**Tunku Abdul Rahman University of Management and Technology**  
**Kuala Lumpur**

*Copyright © 2026/2027 by Tunku Abdul Rahman University of Management and Technology. All rights reserved. No part of this project documentation may be reproduced, stored in a retrieval system, or transmitted in any form or by any means without prior permission of Tunku Abdul Rahman University of Management and Technology.*

---

## Declaration

The project submitted herewith is a result of my own efforts in totality and in every aspect of the project works. All information that has been obtained from other sources has been fully acknowledged. I understand that any plagiarism, cheating, or collusion of any sort constitutes a breach of Tunku Abdul Rahman University of Management and Technology (TAR UMT) rules and regulations and would be subjected to disciplinary actions.

<br/>

_____________________  
**Liew Yi Ler**  
Bachelor of Information Technology (Honours) in Information Security  
Student ID: 25WMR09747  

---

## Abstract

Financial scams and phishing remain the primary cybersecurity threats in Malaysia, precipitating substantial financial losses annually. Conventional defensive mechanisms rely predominantly on static, blacklist-based detection, which routinely fails to mitigate zero-day phishing campaigns and evasive social engineering tactics. To address these critical vulnerabilities, the **PhishGuard-AI** system is proposed as a multi-modal browser security suite. This report specifically details the research, design, and development of the backend module: the **Semantic Threat Intelligence and Mule Account Verification Engine**.

The core objective of this module is to shift web endpoint defence from reactive signature matching to proactive, behavioural artificial intelligence analysis. A Bidirectional Encoder Representations from Transformers (BERT) deep learning model was fine-tuned using domain-specific cybersecurity datasets to perform real-time semantic analysis on Document Object Model (DOM) content and URL strings, effectively identifying psychological urgency cues, brand impersonation triggers, and typosquatting permutations. To combat localized peer-to-peer financial fraud, a Mule Account Verification Engine was developed utilizing pre-compiled Regular Expressions (Regex) and DOM parsing. This engine autonomously extracts Malaysian financial credentials (such as 10-to-14 digit bank accounts and phone numbers) from active webpages and cross-references them against an indexed database modelled after the Royal Malaysia Police (PDRM) CCID *Semakmule* registry.

These services are coordinated via a high-performance Python FastAPI backend utilizing asynchronous execution (`asyncio`), delivering sub-second inference latency to the client-side Google Chrome extension. By uniting contextual Natural Language Processing (NLP) with dynamic credential verification, this backend infrastructure establishes a zero-trust browsing environment capable of neutralizing evasive financial threats with minimal latency.

---

## Acknowledgement

First and foremost, I would like to express my deepest gratitude to my final year project supervisor, **Mr. Tan Yock Khang**, for his invaluable guidance, continuous support, and technical insights throughout the development of this project. His expertise in the field of cybersecurity greatly shaped the direction and academic rigour of this research.

I also wish to extend my appreciation to the **Faculty of Computing and Information Technology (FOCS)** at **Tunku Abdul Rahman University of Management and Technology (TAR UMT)** for providing the computational resources and educational foundation necessary to undertake this endeavour.

Special thanks to my project partner, **Cheon Jie Han**, for his dedication and excellent collaboration on the frontend client integration and visual analysis modules of the PhishGuard-AI system.

Finally, I would like to thank my family and friends for their continuous encouragement, patience, and moral support throughout my academic journey.

---

## Table of Contents

* **Chapter 1: Introduction**
  * 1.1 Background of the Study
  * 1.2 Problem Statement
    * 1.2.1 The Latency of Static Blacklists Against Zero-Day Ephemeral Threats
    * 1.2.2 Evasion via Semantic Manipulation and Contextual Obfuscation
    * 1.2.3 High Friction in the Verification of Localised Mule Accounts
    * 1.2.4 Degradation of the CIA Triad in Digital Transactions
  * 1.3 Objectives
  * 1.4 Solution: The Proposed Framework
    * 1.4.1 Securing Web Browsing with Dynamic Semantic Analysis
    * 1.4.2 Preventing Fraud via Automated Credential Verification
    * 1.4.3 Enhancing System Availability via Asynchronous Microservices
  * 1.5 Target Market
  * 1.6 Advantages & Contributions
  * 1.7 Project Plan
    * 1.7.1 Project Scope
    * 1.7.2 Milestones
    * 1.7.3 Software Development Model
  * 1.8 Project Team & Organization
  * 1.9 Chapter Summary and Evaluation

---

# CHAPTER 1: INTRODUCTION

### 1.1 Background of the Study
In the contemporary era of the Fourth Industrial Revolution (IR 4.0), the global economic landscape has undergone a fundamental paradigm shift towards decentralised, digital financial transactions. Within Malaysia, aggressive national digitalisation initiatives—most notably the **MyDIGITAL blueprint** and the **Bank Negara Malaysia (BNM) Financial Sector Blueprint 2022–2026**—have catalysed the widespread adoption of real-time digital payment gateways. Platforms such as DuitNow, Touch 'n Go eWallet, and integrated online banking ecosystems have fostered unprecedented digital financial inclusion across both urban and rural demographics (Bank Negara Malaysia, 2023).

However, this rapid digitisation has expanded the attack surface for malicious actors, accompanied by an alarming surge in cybercrime. As the technological barrier to entry for digital finance lowers, internet users—many of whom lack formal cybersecurity awareness—are increasingly exposed to sophisticated cyberattacks and financial scams. When personal credentials, session tokens, and financial records are compromised, the consequences are deeply destructive, resulting not only in severe individual financial loss but also in the erosion of public trust in digital banking institutions.

According to empirical statistics reported by CyberSecurity Malaysia and the Royal Malaysia Police (PDRM) Commercial Crime Investigation Department (CCID), financial fraud and phishing constitute the dominant cybersecurity threats within the nation. The financial losses attributed to telecommunication fraud, e-commerce scams, and phishing have grown exponentially. Official metrics indicate that cybercrimes resulted in total financial losses exceeding **RM1.3 billion in 2023 alone**, with predictive trends indicating continuous escalation (CyberSecurity Malaysia, 2024).

Historically, phishing attacks relied on poorly constructed, mass-distributed emails that were easily identifiable by basic heuristics and standard spam filters due to glaring grammatical errors and generic greetings. Today, the threat landscape has evolved into highly targeted, algorithmically generated social engineering campaigns (Alkhalil et al., 2021). Modern threat actors utilise advanced evasion techniques, including Domain Generation Algorithms (DGA), fast-flux hosting networks, and Large Language Models (LLMs) to craft contextually flawless, persuasive text designed to deceive victims (Opara et al., 2023).

To address these national security concerns, this project engineers a secure, proactive, and intelligent browser security suite named **PhishGuard-AI**. The architectural philosophy departs from merely blocking known malicious links via reactive databases; instead, it focuses on embedding Artificial Intelligence (AI) as a real-time defensive mechanism at the endpoint to predict and intercept zero-day threats. Due to the multi-modal complexity of the system, the project is collaboratively divided into two distinct engineering modules: **Visual Identity Analysis (Frontend Client)** and **Semantic Threat Intelligence (Backend Server)**.

This report strictly details the research, design, and development of the **Semantic Threat Intelligence and Mule Account Verification Engine**, which serves as the central orchestration and intelligence backend. By integrating hybrid Deep Learning—specifically Natural Language Processing (NLP) via Bidirectional Encoder Representations from Transformers (BERT)—alongside dynamic data parsing, this module safeguards users against zero-day credential harvesting, malicious DOM manipulation, and money mule account fraud.

---

### 1.2 Problem Statement
Despite continuous advancements in network perimeter security and modern web browsers, end-users remain highly vulnerable to financial fraud due to significant architectural and operational gaps in current defensive technologies:

#### 1.2.1 The Latency of Static Blacklists Against Zero-Day Ephemeral Threats
Traditional web security predominantly relies on deterministic, signature-based blacklists (e.g., DNSBL, Google Safe Browsing, SURBL). However, modern phishing operations utilise automated infrastructure to generate thousands of ephemeral domains daily. Empirical research indicates that over 60% of modern phishing domains remain active for less than two hours (NIST, 2023). The manual or heuristically driven process of discovering a suspicious URL, verifying its maliciousness, and propagating its status to global blacklists introduces a critical "Time-to-Protect" latency spanning several hours to days. Consequently, credential harvesting is frequently completed before the malicious URL is ever indexed by security vendors, rendering reactive defences ineffective against zero-day campaigns.

#### 1.2.2 Evasion via Semantic Manipulation and Contextual Obfuscation
Threat actors increasingly bypass basic keyword and URL filters by employing sophisticated semantic manipulation. This includes typosquatting (e.g., registering `rnaybank.com` instead of `maybank.com`), Internationalised Domain Name (IDN) homograph attacks, and embedding psychological coercion triggers—such as fabricated countdown timers, immediate account suspension warnings, or fraudulent legal notices—within the webpage Document Object Model (DOM). Standard heuristic tools analyse URL strings and keyword frequencies (TF-IDF) without understanding contextual semantics. This lack of deep linguistic comprehension results in high false-negative rates for sophisticated phishing portals that mimic the professional lexicon of legitimate financial institutions (Sahingoz et al., 2019; Opara et al., 2023).

#### 1.2.3 High Friction in the Verification of Localised Mule Accounts
Scammers heavily exploit local e-commerce, social media platforms (e.g., Facebook Marketplace, Telegram), and messaging applications to execute fraudulent peer-to-peer transactions. In the Malaysian context, illicit funds are frequently routed through *"Keldai Akaun"* (Mule Accounts). Currently, verifying whether a counterparty's financial details are linked to criminal records requires users to manually copy the bank account number, navigate away from the application, and query external portals such as the PDRM CCID *Semakmule* platform (Royal Malaysia Police, 2023). This high-friction, multi-step process is rarely performed by users during fast-paced transactions, enabling money mule networks to operate undetected directly on the user's screen.

#### 1.2.4 Degradation of the CIA Triad in Digital Transactions
A successful phishing attack targeting a user's financial credentials initiates a cascading failure that directly compromises the core security principles of the CIA Triad:
* **Confidentiality**: Coercing users into submitting banking credentials or TAC/OTP codes on a fraudulent portal grants attackers unauthorized access to private financial records, destroying data confidentiality.
* **Integrity**: The integrity of the user's financial state is severely compromised, enabling unauthorized modification of account details, altering beneficiary data, or executing unauthorized wire transfers.
* **Availability**: Attacks threaten availability by locking legitimate users out of their banking sessions once credentials and recovery mechanisms are altered by an adversary.

---

### 1.3 Objectives
The primary goal of this module is to engineer a secure, highly scalable, AI-driven backend infrastructure capable of dynamically analysing web semantics and verifying financial credentials in real time. The specific objectives are:
1. **To engineer a Semantic Threat Intelligence Engine for high-accuracy, real-time zero-day classification.** To replace reactive blacklists, a Bidirectional Encoder Representations from Transformers (BERT) deep learning model is fine-tuned to classify intercepted URL strings and raw webpage text. The model identifies typosquatting, urgency triggers, and complex social engineering patterns within the DOM to prevent credential harvesting.
2. **To design and implement a Localised Mule Account Verification Engine to detect fraudulent payment endpoints.** To prevent unauthorized fund transfers to illicit syndicates, an automated scanning mechanism is developed utilizing pre-compiled Regular Expressions (Regex) and DOM parsing. The engine extracts Malaysian financial credentials (10-to-14 digit bank account and telephone numbers) from rendered DOM content and cross-references them against an indexed database in real time.
3. **To develop a robust, asynchronous Python FastAPI backend architecture to ensure high availability and sub-second response times.** To achieve high computational throughput without degrading client browsing performance, a concurrent backend infrastructure is built utilizing FastAPI and Uvicorn over an Asynchronous Server Gateway Interface (ASGI). Heavy neural network tensor computations are offloaded to dedicated worker threads (`asyncio.to_thread`), guaranteeing sub-second latency for client extension requests.

---

### 1.4 Solution: The Proposed Framework
To mitigate the vulnerabilities identified in Section 1.2, the PhishGuard-AI backend implements a multi-layered, proactive defence framework:

#### 1.4.1 Securing Web Browsing with Dynamic Semantic Analysis
To overcome zero-day blacklist latency, the solution deploys a fine-tuned BERT deep learning model. This provides adaptive intelligence capable of tokenizing, contextualizing, and evaluating webpage semantics in real time. Even if a phishing domain was registered only minutes prior to the visit, the model identifies manipulative language within the DOM and flags the threat immediately, shifting endpoint defence from reactive signature matching to proactive behavioural classification.

#### 1.4.2 Preventing Fraud via Automated Credential Verification
To eliminate the friction of manual mule account lookups, the system introduces an automated background verification engine. The Python backend parses DOM text extracted by the client extension, extracts candidate Malaysian bank account numbers using optimized Regex patterns, and cross-references them against an internal SQLite 3NF database of flagged accounts. This neutralizes peer-to-peer payment fraud without requiring manual user context-switching.

#### 1.4.3 Enhancing System Availability via Asynchronous Microservices
To ensure deep learning inference does not introduce latency into the browsing experience, the backend is architected as an asynchronous microservice. Utilizing FastAPI, non-blocking I/O, and SQLite WAL (Write-Ahead Logging) mode, heavy tensor computations execute concurrently with database queries, maintaining sub-second response times and high availability under heavy network loads (Bansal & Ouda, 2022).

---

### 1.5 Target Market
The PhishGuard-AI system is engineered to safeguard demographics vulnerable to digital financial fraud:
* **Primary Users**:
  * **General Public and Vulnerable Demographics**: Internet users engaging in daily e-commerce and banking who lack specialized cybersecurity knowledge to detect homograph URLs, subtle typosquatting, or psychological coercion cues.
  * **SME Personnel**: Small and Medium Enterprise employees handling corporate procurement and invoices who require protection against targeted Business Email Compromise (BEC) and fake payment portals.
* **Secondary Users**:
  * **Financial Institutions (Banks & Fintech Operators)**: Security operations teams seeking to reduce unauthorized transactions and brand impersonation campaigns targeting their customers.
  * **Corporate IT Administrators**: System administrators requiring lightweight, API-driven endpoint protection to prevent credential leakage on internal networks.

---

### 1.6 Advantages & Contributions
* **Enhanced Data Privacy & Confidentiality**: Threat detection occurs via an on-premises / localized backend service rather than transmitting sensitive DOM content to third-party public cloud LLMs, upholding user data privacy.
* **Restoration of Consumer Trust in Digital Transactions**: Direct verification of money mule accounts neutralizes e-commerce fraud vectors, reinforcing public confidence in national digital payment systems.
* **Alignment with UN Sustainable Development Goals (SDGs)**: Directly contributes to **SDG 9** (*Industry, Innovation, and Infrastructure*) by strengthening resilient digital infrastructure and **SDG 16** (*Peace, Justice, and Strong Institutions*) by actively countering organized financial cybercrime syndicates (United Nations, 2015).

---

### 1.7 Project Plan

#### 1.7.1 Project Scope
The PhishGuard-AI system is divided into two distinct engineering modules: the **Backend API & Intelligence Architecture** and the **Frontend Browser Extension Architecture**.

This report focuses strictly on the backend intelligence, API routing, database engineering, and semantic AI model training. The frontend development—encompassing Manifest V3 Chrome Extension architecture, DOM manipulation for user alerts, headless screenshot capture, and CNN-based visual logo detection—falls under the scope of project partner Cheon Jie Han and is documented in a separate report.

Table 1.1 delineates the functional task allocation between both project members.

**Table 1.1: System Modules and Task Allocation**
| System Module | Description | Member Assigned |
| :--- | :--- | :--- |
| **Semantic Threat Intelligence Engine** | Develops the NLP pipeline for phishing classification. Fine-tunes and evaluates the BERT model to identify malicious semantics, urgency cues, and typosquatting patterns from DOM text and URLs. | Liew Yi Ler |
| **Mule Account Database Engineering** | Designs and maintains the SQLite database of flagged mule accounts. Implements Regex algorithms to extract 10-to-14 digit Malaysian bank account numbers from webpage content and cross-checks them in real time. | Liew Yi Ler |
| **Backend API Gateway (FastAPI)** | Develops the asynchronous FastAPI backend server coordinating communication between client extensions and AI models. Handles async routing, PyTorch inference offloading, and structured JSON response formatting. | Liew Yi Ler |
| **Visual Identity Analysis (CNN)** | Develops the computer vision model utilizing the PhishPedia dataset to identify logos of legitimate Malaysian financial institutions and detect visual brand impersonation. | Cheon Jie Han |
| **Client-Side Browser Integration** | Implements the Google Chrome Extension using Manifest V3 (Service Workers, Content Scripts, and Popups) to extract webpage DOM data, interface with the backend API, and display threat warning overlays. | Cheon Jie Han |

#### 1.7.2 Milestones
The project schedule is structured across two consecutive semesters (Project I and Project II), detailed in Table 1.2.

**Table 1.2: Project Schedule & Milestones**
| Activity / Deliverable | Description | Completion Date |
| :--- | :--- | :--- |
| **Project Proposal Submission** | Preparation and submission of project title, objectives, scope, methodology, and approval forms. | June 2026 |
| **Proposal Moderation** | Presentation of project plan for moderation; incorporation of supervisor and panel feedback. | June 2026 |
| **Chapter 1 Submission** | Submission of Introduction covering background, problem statement, objectives, and planning. | July 2026 |
| **Chapter 2 Submission** | Submission of Literature Review analyzing existing phishing detection paradigms and state-of-the-art models. | August 2026 |
| **Chapter 3 Submission** | Submission of Methodology and Requirements Analysis defining functional and non-functional specifications. | September 2026 |
| **Chapter 4 Submission** | Submission of System Design detailing software architecture, UML diagrams, database schemas, and algorithms. | October 2026 |
| **Project I Portfolio Submission** | Compilation and submission of the comprehensive Project I portfolio and progress deliverables. | November 2026 |
| **Test Plan & Prototype Demonstration** | Execution of preliminary integration testing and demonstration of working prototype to supervisor. | December 2026 |
| **Final System Testing & Validation** | Execution of comprehensive functional, performance, and security testing with supervisor and moderator. | January 2027 |
| **Draft FYP Report Submission** | Submission of full draft dissertation report for supervisor review and refinement. | February 2027 |
| **Final Report & Deliverables Submission** | Submission of final bound report, source code repository, documentation, and presentation materials. | March 2027 |

#### 1.7.3 Software Development Model
The development framework combines **Agile Methodology** with **Machine Learning Operations (MLOps)**:
* **Agile Methodology**: Manages iterative development sprints for software components (FastAPI route creation, Regex optimization, database migration), ensuring flexibility as technical requirements evolve (Beck et al., 2001).
* **MLOps Principles**: Integrates continuous machine learning lifecycle management into development sprints, treating dataset balancing, tokenization tuning, hyperparameter optimization, and model evaluation (F1-score, Precision-Recall curves) as ongoing iterative activities rather than post-hoc steps (Kreuzberger et al., 2023).

---

### 1.8 Project Team & Organization
* **Liew Yi Ler** (Student ID: 25WMR09747) – Backend Intelligence, Semantic AI (BERT), Mule Registry, and FastAPI Architecture.
* **Cheon Jie Han** (Student ID: 25WMR09703) – Frontend Client, Manifest V3 Extension, Visual Identity (CNN), and User Interface.

**Table 1.3: Project Organization & Component Ownership**
| Subsystem Area | Backend Server (Python / FastAPI) | Frontend Client (Chrome Extension) |
| :--- | :--- | :--- |
| **Semantic Intelligence (BERT)** | **Liew Yi Ler** – Fine-tunes and deploys BERT model for semantic classification and urgency detection. | — |
| **Mule Account Verification** | **Liew Yi Ler** – Implements Regex extraction algorithms and SQLite 3NF database query engine. | — |
| **API Gateway & Routing** | **Liew Yi Ler** – Constructs asynchronous FastAPI ASGI server and structured JSON schemas. | — |
| **Visual Identity Analysis** | — | **Cheon Jie Han** – Develops CNN logo classification and brand impersonation detection. |
| **DOM Interception & Content Script** | — | **Cheon Jie Han** – Implements Manifest V3 content scripts for DOM/text extraction. |
| **User Interface & Alerts** | — | **Cheon Jie Han** – Designs popup UI, alert overlays, and telemetry dashboards. |
| **End-to-End System Integration** | **Liew Yi Ler** – Integrates backend AI models and API services. | **Cheon Jie Han** – Connects extension client to backend endpoints. |

---

### 1.9 Chapter Summary and Evaluation
This chapter established the foundational framework for the proposed **PhishGuard-AI** system. The critical limitations of conventional static blacklists—namely zero-day latency, semantic evasion, and manual friction in mule account verification—were thoroughly examined in the context of Malaysia's accelerating digital economy. To remediate these challenges, the project formulates a proactive, multi-modal backend architecture incorporating a fine-tuned BERT deep learning engine, an automated Regex-based mule account lookup system, and an asynchronous FastAPI service layer.

Furthermore, target demographic segments, socio-economic benefits, and alignments with UN Sustainable Development Goals (SDG 9 and SDG 16) were established. Finally, the project plan, functional milestone schedule, Agile-MLOps hybrid methodology, and collaborative team organization were defined, establishing the operational roadmap for the subsequent literature review and system design chapters.
