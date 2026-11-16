<!-- Generated from PhishGuard-AI_Project_1_&_2_Report_LiewYiLer.docx (v3.2.0, 16 November 2026). The Word document is the authoritative version; edit it, not this file. -->

# Chapter 2

## Literature Review

### 2.1 Introduction & Scope of Literature Review

The exponential proliferation of digital financial fraud, credential harvesting, and sophisticated social engineering campaigns represents an existential challenge to modern internet infrastructure. Developing a real-time client-server cybersecurity platform capable of intercepting elusive "Zero-Day" phishing campaigns necessitates a rigorous, systematic evaluation of existing academic literature and industrial defensive paradigms.

Historically, web security architectures have operated under reactive, perimeter-focused philosophies. However, modern threat syndicates have shifted their primary attack vector from penetrating hardened network boundaries to exploiting the cognitive vulnerabilities of end-users through deceptive semantic interfaces and localised money mule syndicates. This chapter conducts a comprehensive, critical review of the state of the art in web threat detection.

Specifically, this review investigates:

- The structural transformation of digital banking and real-time payment ecosystems in Southeast Asia.
- The psychological mechanics of cognitive bias exploitation ("System 1" heuristic bypass).
- The contemporary industrialisation of cybercrime through Phishing-as-a-Service (PhaaS) and semantic obfuscation.
- Theoretical cybersecurity frameworks including the CIA Triad degradation model and Zero Trust Architecture (ZTA) at the browser edge.
- The mathematical and computational evolution of Natural Language Processing (NLP) from Bag-of-Words (TF-IDF) to Bidirectional Encoder Representations from Transformers (BERT).
- Deterministic vs. probabilistic credential extraction methodologies (Regex vs. Named Entity Recognition).
- High-concurrency backend microservice paradigms (Synchronous WSGI vs. Asynchronous ASGI event loops).
- The critical research gaps in localised, real-time client-side threat intelligence that the **Semantic Threat Intelligence and Mule Account Verification Engine** (developed by Liew Yi Ler) is specifically engineered to resolve.

### 2.2 Digital Transformation in Financial Ecosystems & Threat Surface Expansion

#### 2.2.1 The Role and Reliance on Digital Banking Platforms

The global financial landscape has undergone an irreversible structural migration toward decentralised, cloud-native digital banking and real-time electronic fund transfer platforms. Within Malaysia and the broader ASEAN region, regulatory initiatives such as the **Bank Negara Malaysia (BNM) Financial Sector Blueprint 2022–2026** and the national **MyDIGITAL** strategy have mandated the implementation of open banking APIs and standardised instant payment switches (Bank Negara Malaysia, 2023).

Platforms such as the **DuitNow** real-time payment network (operated by Payments Network Malaysia / PayNet), integrated Financial Process Exchange (FPX) gateways, and mobile e-wallets (e.g., Touch 'n Go eWallet, GrabPay, Boost) have achieved near-universal penetration across consumer and commercial sectors.

*[Figure: see the Word report]*

While these integrated architectures provide frictionless financial inclusion, they centralise immense volumes of liquid capital and personally identifiable information (PII). In open banking architectures, access control is mediated almost entirely through user credentials, session cookies, and multi-factor authentication (MFA) tokens.

Consequently, digital banking platforms exhibit a critical architectural vulnerability: a **Single Point of Failure (SPOF)** located at the unauthenticated human endpoint. If an attacker deceives a user into authenticating on a visually identical proxy portal, the entire security perimeter of the underlying financial institution is compromised, exposing the victim's liquid assets to immediate exfiltration (Alkhalil et al., 2021).

#### 2.2.2 The Vulnerability of the Human Element and Cognitive Biases

While commercial banks deploy enterprise-grade infrastructure defences including Tier-4 data centre firewalls, Web Application Firewalls (WAF), database encryption, and automated anomaly detection the human operator remains the most vulnerable component in the security chain. Threat actors increasingly bypass technical perimeter firewalls entirely by weaponising psychological social engineering.

*[Figure: see the Word report]*

Behavioural cybersecurity literature grounds this vulnerability in **Dual-Process Cognitive Theory** (Kahneman, 2011). Human cognition is divided into two distinct processing modalities:

- **System 1 (Intuitive & Fast)**: Operates automatically, rapidly, and emotionally with minimal conscious computational effort.
- **System 2 (Analytical & Slow)**: Allocates attention to effortful mental operations, including rigorous logical deduction and critical verification.
Phishing campaigns are engineered to trigger System 1 responses while actively suppressing System 2 engagement (Vishwanath et al., 2011). Attackers embed coercive psychological stimuli into webpage Document Object Models (DOM) such as fabricated legal threats, countdown timers threatening immediate account closure, or bogus security alerts. Under acute psychological duress, users rely on visual heuristics (e.g., recognising a familiar bank logo) while overlooking critical indicators of compromise (e.g., misspelt domain names or anomalous SSL certificates).

This fundamental cognitive limitation demonstrates that relying on user vigilance or security awareness training is insufficient; automated, client-side intelligence is mandatory to intercept threats before user interaction occurs.

### 2.3 Contemporary Cybersecurity Threat Landscape in Digital Finance

#### 2.3.1 Phishing-as-a-Service (PhaaS) and the Monetisation of Credentials

The cybercrime ecosystem has evolved from fragmented, individual script kiddies into industrialised, corporate-style syndicates operating under the **Phishing-as-a-Service (PhaaS)** business model. Dark web marketplaces distribute fully packaged, subscription-based phishing toolkits (e.g., EvilProxy, Modlishka, Greatness) that incorporate automated reverse proxies capable of executing Adversary-in-the-Middle (AiTM) attacks in real time (Kondracki et al., 2021).

*[Figure: see the Word report]*

These sophisticated toolkits intercept session tokens, bypassing legacy Multi-Factor Authentication (MFA) mechanisms. Stolen credentials and valid session cookies are monetised immediately across illicit channels, fueling secondary Business Email Compromise (BEC), unauthorised wire transfers, and identity impersonation rings.

#### 2.3.2 Empirical Threat Landscape in Malaysia

In Malaysia, financial scams have escalated into a critical national threat. According to empirical data compiled by **CyberSecurity Malaysia** and the **Royal Malaysia Police (PDRM) CCID**, over **34,000 cases of online fraud** were officially investigated in 2023 alone, generating direct financial losses exceeding **RM1.3 billion** (CyberSecurity Malaysia, 2024; Royal Malaysia Police, 2024).

*[Figure: see the Word report]*

A significant portion of these attacks involve hyper-localised clones of major domestic financial institutions including Malayan Banking Berhad (Maybank2u), CIMB Group Holdings (CIMB Clicks), Public Bank Berhad (PBe), RHB Bank, Hong Leong Bank, and statutory agencies such as the Employees Provident Fund (KWSP/EPF) and Lembaga Hasil Dalam Negeri (LHDN).

In almost every domestic fraud case, illicitly extracted funds are funnelled through **"Keldai Akaun" (Money Mule Accounts)** bank accounts owned by third parties who lease their banking credentials to scam syndicates. The rapid movement of capital through multi-layered mule accounts presents an extreme challenge to law enforcement, making real-time endpoint interception vital before fund transfer initiation.

#### 2.3.3 Semantic Obfuscation, Punycode, and Typosquatting

To evade detection by heuristic scanners and static security rules, threat actors employ multi-layered syntactic and semantic obfuscation:

- **Internationalised Domain Name (IDN) Homoglyph Attacks**:Attackers register domain names containing non-Latin Unicode characters (e.g., Cyrillic а (U+0430) vs. Latin a (U+0061)). Web browsers parse these strings using **Punycode** algorithms (e.g., xn--mybnk-fra.com), rendering visual representations indistinguishable from legitimate financial domains to the human eye.
- **Typosquatting & Combosquatting**:Attackers register lookalike domains exploiting common typographical errors or visual character substitutions (e.g., substituting the letters r and n for m to create rnaybank.com, or adding deceptive security keywords such as maybank-verification-secure.com). Mathematically, these strings maintain a minimal **Levenshtein Distance** () relative to legitimate banking domains:
*[Figure: see the Word report]*

- **Multilingual Social Engineering**:In Southeast Asia, phishing narratives are crafted using localised linguistic blending (Bahasa Melayu, English, and colloquial Manglish). Phrases such as "Tindakan Segera: Akaun Maybank anda telah dibekukan. Sila log masuk untuk kemaskini TAC anda sekarang" utilise cultural urgency idioms that standard global English-only heuristic filters completely fail to identify.
**2.3.4 Optical Quishing (QR Phishing) Exploitation**

A rapidly emerging vector in digital payment ecosystems is **Quishing (QR Code Phishing)**. Threat actors replace standard web hyperlinks with embedded QR code images containing encoded DuitNow payment strings conforming to the **EMVCo Merchant-Presented QR Code Specification**.

Traditional web scrapers and heuristic classifiers analyse DOM text and <a href> attributes; because the malicious redirection payload is rendered purely as an optical matrix barcode, standard text-based security systems are completely bypassed. This highlights the necessity for integrated optical computer vision decoders inside the threat intelligence pipeline.

### 2.4 Theoretical Cybersecurity & Architectural Frameworks

#### 2.4.1 The CIA Triad in Phishing Mitigation

The design of the PhishGuard-AI backend architecture is rooted in the formal preservation of the **CIA Triad (Confidentiality, Integrity, and Availability)**:

*[Figure: see the Word report]*

- **Confidentiality**: A successful phishing attack destroys data confidentiality by coercing victims into disclosing usernames, passwords, and banking authorisation tokens. PhishGuard-AI enforces confidentiality by intercepting and evaluating raw DOM payloads at the edge before user credential entry can occur.
- **Integrity**: When an unauthorised adversary acquires valid session credentials, the integrity of the user's financial state is severely compromised through unauthorised fund transfers and altered account settings. PhishGuard-AI protects integrity by validating beneficiary credentials against simulated law enforcement databases in real time.
- **Availability**: Adversaries routinely lock victims out of legitimate financial accounts by resetting authentication credentials. Concurrently, defensive security tools must ensure their own high availability; PhishGuard-AI achieves this through an asynchronous microservice architecture providing sub-second threat decisions without disrupting browser responsiveness.

#### 2.4.2 Zero Trust Architecture (ZTA) at the Browser Edge

Traditional perimeter security operated under the "castle-and-moat" paradigm, assuming that any traffic originating inside an internal network or secured via an SSL/TLS certificate was inherently trustworthy. The widespread availability of free, automated SSL certificates (e.g., Let's Encrypt, Cloudflare Universal SSL) has rendered the browser "padlock" icon useless as a trust indicator; over **80% of active phishing sites now operate over valid HTTPS connections** (APWG, 2023).

PhishGuard-AI operationalises the **Zero Trust Architecture (ZTA)** framework defined in **NIST Special Publication 800-207**, adhering strictly to the axiom: **"Never Trust, Always Verify"** (Rose et al., 2020).

*[Figure: see the Word report]*

Under this model, every intercepted DOM payload, URL string, and embedded visual asset is treated as hostile. Regardless of whether a domain has a valid HTTPS certificate or a benign IP reputation, the backend mathematically inspects the semantic intent and credential structure before granting user interaction privileges.

#### 2.4.3 OWASP Top 10 & The Secure Development Lifecycle (SDL)

Phishing and credential stuffing exploit core vulnerabilities documented in the **OWASP Top 10 Web Application Security Risks**:

- **A01:2021 – Broken Access Control**: Attackers hijack session tokens to bypass authorisation boundaries.
- **A07:2021 – Identification and Authentication Failures**: Absence of real-time endpoint verification allows cloned login interfaces to harvest primary authentication secrets.
To ensure software resilience, this research implements the **Microsoft Secure Development Lifecycle (SDL)** integrated with **Machine Learning Operations (MLOps)** (Kreuzberger et al., 2023). Threat modelling, rigorous input sanitisation, rate limiting, and automated regression testing are treated as continuous engineering constraints throughout development.

### 2.5 Critical Evaluation of Technical Anti-Phishing Countermeasures

#### 2.5.1 The Shift from Static Blacklists to Machine Learning

The foundational baseline for internet threat prevention has historically relied on deterministic, signature-based blacklists (e.g., Google Safe Browsing, PhishTank, Spamhaus, SURBL). While blacklists provide near-zero false-positive rates for previously identified threats, their operational architecture is fundamentally reactive (Alabdan, 2020).

*[Figure: see the Word report]*

The fatal flaw of static blacklists is the **Time-to-Protect Latency Gap** (ΔTprotect​): 

*[Figure: see the Word report]*

Where modern automated phishing campaigns exhibit an operational lifespan () that is short relative to the defender's response. In a year-long measurement covering 4.8 million victim visits, Oest et al. (2020) found that the average campaign was over within 21 hours of its first victim, while detection by anti-phishing entities came on average nine hours after that first visit, with a further delay before browser warnings reached their peak. Blacklists therefore leave an exposure window at the start of every campaign, which motivates predictive models that evaluate threats based on intrinsic behavioural features rather than historical reputations.

#### 2.5.2 Evolution of Natural Language Processing in Threat Detection

*[Figure: see the Word report]*

The application of Natural Language Processing (NLP) to web security has progressed through three major paradigms:

**1. Lexical and Statistical Feature Extraction (TF-IDF + Traditional ML)**

Early automated solutions utilised term frequency statistics specifically **Term Frequency-Inverse Document Frequency (TF-IDF)** paired with Support Vector Machines (SVM), Random Forests, or Naive Bayes classifiers (Sahingoz et al., 2019):

*[Figure: see the Word report]*

While computationally lightweight, TF-IDF operates on a **Bag-of-Words (BoW)** assumption that discards syntactic word order and contextual semantic meaning. These models fail when encountering synonyms, obfuscated spellings, or multilingual Manglish phrasing.

**2. Sequential Deep Learning Architectures (RNN & LSTM)**

To capture word ordering, researchers deployed Recurrent Neural Networks (RNN) and **Long Short-Term Memory (LSTM)** networks. LSTMs utilise gating mechanisms (Input, Forget, and Output gates) to maintain sequential state across text tokens:

*[Figure: see the Word report]*

Although LSTMs improved sequential text comprehension, their **strictly sequential computation** prevents hardware parallelisation on modern GPUs/multi-core CPUs. Furthermore, LSTMs suffer from performance degradation on lengthy DOM structures due to the vanishing gradient problem, making them too slow for real-time endpoint interceptors (Maneriker et al., 2021).

**3. Transformer Architectures & BERT**

The introduction of the **Transformer** by Vaswani et al. (2017) revolutionised NLP through the **Scaled Dot-Product Self-Attention** mechanism:

*[Figure: see the Word report]*

Where Q (Query), K (Key), and V (Value) represent linear projections of the input token embeddings, and d_k represents the dimensionality of the key vectors. By computing attention weights across all tokens simultaneously, Transformers achieve massive computational parallelisation.

Building upon this, Devlin et al. (2018) introduced **BERT (Bidirectional Encoder Representations from Transformers)**. Unlike previous unidirectional models, BERT utilises a Masked Language Model (MLM) pre-training objective, allowing token embeddings to capture context from both left and right directions across all layers.

*[Figure: see the Word report]*

An advantage of BERT in this setting is its WordPiece subword tokenisation. When an attacker employs typosquatting (e.g., rnaybank), a word-level model fails because the token is Out-Of-Vocabulary (OOV). BERT breaks the string into subword units (rn, ##ay, ##bank), which lets the model relate the fragments to tokens it has seen in training; Maneriker et al. (2021) report that Transformer models fine-tuned on URLs outperform earlier deep URL classifiers at low false-positive rates. Subword tokenisation is not, however, a guarantee of look-alike detection: it gives the model the opportunity to learn such patterns, and whether it does depends on the training data. This project therefore complements BERT with an explicit edit-distance and homoglyph check (Section 4.6).

**Table 2.1: Comprehensive Comparative Matrix of NLP Architectures in Threat Detection**

| Technical Dimension | Traditional ML (TF-IDF + SVM) | Recurrent Models (LSTM / BiLSTM) | Transformer Architecture (BERT) |
| --- | --- | --- | --- |
| Handling of Typosquatting | Poor; fails on Out-Of-Vocabulary (OOV) tokens | Moderate; requires complex character embeddings | Good where similar patterns occur in training; subword units help, but look-alike domains are caught more reliably by an explicit edit-distance check |
| Computational Parallelism | High (static matrix multiplication) | Extremely Low (strictly sequential step computation) | High (matrix dot-product optimised for SIMD/GPUs) |
| Inference Latency | Lowest (sparse linear model) | Moderate; grows with sequence length because tokens are processed in order | Highest per item; about 108 ms per URL on CPU in this project (Section 5.5.2) |
| Zero-Day Generalization | Very Low; relies on exact keyword frequencies | Moderate; susceptible to long-range memory decay | Good within the training distribution; degrades under distribution shift (Section 5.5.2) |

#### 2.5.3 Automated Financial Credential Extraction: Regex vs. NER

While probabilistic deep learning is optimal for evaluating ambiguous natural language, verifying financial credentials requires **100% deterministic precision**. In the Malaysian financial sector, scam syndicates rely on direct transfers to domestic bank accounts.

To automate credential extraction from unstructured webpage DOM text, two primary paradigms exist:

- **Named Entity Recognition (NER)** (e.g., SpaCy, Stanford NER, BERT-NER): Evaluates surrounding sentence tokens to predict entity classes (e.g., ORG, MONEY, ACCOUNT).
- **Deterministic Regular Expressions (Regex)**: Executes pre-compiled finite state automata to match explicit numerical formatting rules.
*[Figure: see the Word report]*

**Table 2.2: Comparison of Financial Extraction Paradigms for Malaysian Banking Formats**

| Evaluation Criterion | Named Entity Recognition (NER - SpaCy/BERT) | Pre-Compiled Regular Expressions (Regex Bytecode) |
| --- | --- | --- |
| Extraction Precision | Probabilistic; depends on labelled training sentences | Deterministic for a given format; cannot distinguish an account from another number of the same shape |
| Execution Latency | A model forward pass per page | Negligible for compiled patterns on page-sized text |
| Domain Specificity | Requires thousands of labelled training sentences | Encodes the length and prefix conventions of each bank's account numbers (approximations, not an official specification) |
| Edge Resource Footprint | Large (Transformer-based NER models occupy hundreds of megabytes) | Negligible |

Because Malaysian bank account numbers follow fixed length and prefix conventions, pre-compiled regular expressions coupled with an indexed SQLite lookup extract and verify candidate accounts deterministically and at negligible cost. The limitation of the approach is equally clear: a pattern cannot tell a bank account from an order number of the same length, so extraction alone must never trigger a block; only a match against the registry does.

#### 2.5.4 High-Concurrency Backend Architectures (WSGI vs. ASGI)

Deploying computationally intensive deep learning models for real-time web defence presents severe concurrency challenges. A single browser client visiting a webpage generates multiple asynchronous HTTP inspection requests. In enterprise deployments handling thousands of concurrent users, traditional synchronous backend architectures fail catastrophically.

*[Figure: see the Word report]*

**1. Web Server Gateway Interface (WSGI) Limitations**

Traditional Python frameworks (Flask, Django) implement the **WSGI** specification. WSGI operates synchronously: each incoming request binds an entire operating system worker thread until the request completes. When an incoming request triggers heavy PyTorch tensor calculations, the worker thread locks the Python **Global Interpreter Lock (GIL)**. Concurrent incoming requests are placed in an operating system backlog queue, resulting in thread starvation, dropped packets, and latency spikes exceeding 2.0 seconds (Bansal & Ouda, 2022).

**2. Asynchronous Server Gateway Interface (ASGI) & FastAPI**

Modern asynchronous frameworks specifically **FastAPI** running on the **Uvicorn** ASGI server utilise Python's native asyncio non-blocking event loop. To prevent heavy tensor calculations from stalling the event loop, CPU-bound machine learning tasks are dispatched to separate thread pools using asyncio.to_thread():

# Asynchronous Non-Blocking Execution Pattern in PhishGuard-AI

async def analyze_threat(payload: ThreatPayload) -> ThreatVerdict:

    # Execute CPU-bound BERT tensor calculations in thread pool

    bert_task = asyncio.to_thread(self._bert_inference, payload.sanitized_dom)

    # Execute non-blocking asynchronous database I/O

    mule_task = self._mule_scanner.query_account(payload.extracted_account)

    # Run tasks concurrently in parallel

    bert_score, mule_match = await asyncio.gather(bert_task, mule_task)

    return self._aggregate_verdict(bert_score, mule_match)

By pairing asyncio.to_thread() with an asynchronous SQLite connection (aiosqlite), FastAPI serves other requests while a forward pass is running, keeping the event loop free while inference is in progress.

**Table 2.3: Architecture Performance Comparison: Synchronous WSGI vs. Asynchronous ASGI**

| Architectural Metric | Synchronous WSGI (Flask + Gunicorn) | Asynchronous ASGI (FastAPI + Uvicorn) |
| --- | --- | --- |
| Concurrency Paradigm | 1 Worker Thread = 1 Request (Synchronous Blocking) | Single Event Loop + Asynchronous Non-Blocking Coroutines |
| GIL Handling for AI | Locks the entire worker thread during tensor operations | Dispatches AI tensors to worker threads (asyncio.to_thread) |
| Database I/O Strategy | Synchronous blocking SQL drivers | Asynchronous non-blocking connection pool (aiosqlite) |
| Throughput (Requests/sec) | Bounded by the number of workers, each blocked for the duration of a request | Measured in this project: 22.4 req/s at 50 users; about 10–11 uncached BERT inferences per second on one CPU worker (Section 5.5.3) |
| Average Decision Latency | Grows with queueing once every worker is busy | Measured in this project: median 190 ms, p95 450 ms on the BERT path at 50 users |

### 2.6 Research Gaps, Comparative Synthesis, and Conceptual Framework

#### 2.6.1 Identification of Key Research Gaps

A critical synthesis of contemporary literature reveals three fundamental research gaps in web threat detection:

*[Figure: see the Word report]*

#### 2.6.2 Comparative Analysis of Existing State-of-the-Art Solutions

To position PhishGuard-AI within the broader security landscape, Table 2.4 compares the proposed system against prominent academic and commercial anti-phishing platforms.

**Table 2.4: Comparative Matrix of PhishGuard-AI against Existing Defensive Solutions**

| Feature / Capability | Google Safe Browsing (2024) | Netcraft Anti-Phishing Extension | PhishPedia (Lin et al., 2021) | PhishGuard-AI (Proposed System) |
| --- | --- | --- | --- | --- |
| Primary Detection Engine | Static URL Blacklist + Client Heuristics | Blacklist + Server-Side Certificate Audit | Deep Learning Computer Vision (CNN) | Hybrid Multi-Modal (BERT URL model + rule corroboration + YOLOv8 vision + Regex) |
| Zero-Day Ephemeral Defense | ⚠️ Limited by detection and list-propagation delay (Oest et al., 2020) | ⚠️ Moderate (Relies on crawler verification) | ✅ High (Visual logo matching) | ✅ Evaluated per page at request time, so no propagation lag (median 190 ms) |
| Typosquatting / Subword Parsing | ❌ Ineffective against novel DGAs | ⚠️ Basic domain distance matching | ❌ Irrelevant (Image-only analysis) | ✅ High (look-alike domain detection + BERT URL classifier) |
| Localized Mule Account Verification | ❌ None | ❌ None | ❌ None | ✅ Automated (8-bank Regex + SQLite; simulated registry) |
| Multi-Lingual / Manglish Support | ❌ English-Centric | ❌ English-Centric | N/A (Visual) | ⚠️ Partial: English-only BERT; multilingual scam lexicon and brand rules |
| Enterprise SOC & Law Enforcement CTI | ❌ Closed proprietary ecosystem | ⚠️ Basic enterprise report feed | ❌ Research prototype only | ✅ SSE telemetry, STIX 2.1 / CEF export and NSRC-format case summaries (no live government link) |
| Decision Latency SLA | Fast (local list lookup) | Not published | Requires a rendered screenshot and a GPU for interactive speed | Median 190 ms, p95 450 ms on the BERT path (50 users, CPU) |

*[Figure: see the Word report]*

#### 2.6.3 Critical Synthesis of Architectural Trade-offs

The solutions surveyed above are usually presented by their authors as alternatives. Read together, they are better understood as detectors of different evidence, each with a characteristic failure mode. The design question for this project is therefore not which single technique is best, but which combination covers the others' blind spots at an acceptable cost in latency and false alarms.

**Lexical and Transformer URL models.** URLNet (Le et al., 2018) and URLTran (Maneriker et al., 2021) classify the URL string alone, which makes them fast and independent of page rendering. Their weakness is what they cannot see: a phishing kit hosted on a compromised or neutral domain carries no lexical signal, and a legitimate deep link with a long path and the word login can look suspicious. Reported accuracies above 98% must also be read with care. Arp et al. (2022) show that sampling bias, data snooping and inappropriate baselines are widespread in security machine-learning studies, and Dalton et al. (2025) demonstrate specifically for phishing that leakage between training and test splits and unrealistic base rates lead to overly optimistic results. A random split of a URL corpus, as used in many studies and in this project's own fine-tuning run, places URLs from the same campaign and the same host on both sides of the split.

**Content-based and hybrid feature models.** Approaches that add HTML features to the URL (Aljofey et al., 2022; Hannousse & Yahiouche, 2021) gain access to forms, links and text, at the cost of fetching and parsing the page. Hannousse and Yahiouche (2021) also show that results vary considerably with dataset construction, which again limits how far a single headline figure can be trusted.

**Reference-based visual models.** Phishpedia (Lin et al., 2021), VisualPhishNet (Abdelnabi et al., 2020) and PhishIntention (Liu et al., 2022) identify the brand a page presents, by logo or overall appearance, and flag a mismatch with the domain. This is the most direct test of impersonation and is robust to textual obfuscation, but it depends on a maintained reference list of protected brands, requires a rendered screenshot, and is typically run on a GPU. Recent work replaces the fixed reference list with knowledge drawn from large language models (Li et al., 2024; Liu et al., 2024) and reports substantially more zero-day detections, at the price of sending page content to a remote model, with the latency, cost and data-protection implications discussed in Section 6.2. Koide et al. (2023) similarly show that a general-purpose language model can judge phishing pages well, under the same constraints.

**Blacklists and heuristics.** Blacklists remain the only approach with a near-zero false-positive rate for known threats and negligible latency, but they protect nobody during the first hours of a campaign (Oest et al., 2020). Hand-written heuristics are transparent and cheap, yet brittle when used alone.

**Dataset limitations for the Malaysian context.** The public corpora behind these systems are dominated by English-language pages and global brands. To the author's knowledge there is no public labelled corpus of Malaysian financial scam pages in Bahasa Melayu or Manglish, and none that links pages to the mule accounts they advertise. Fraudulent e-commerce and payment-diversion pages, which are closer to the Malaysian mule problem than classic credential phishing, have only recently been studied at scale (Bitaab et al., 2023). Any model trained on the available corpora therefore faces a distribution shift when applied to Malaysian content, a prediction that Section 5.5.2 confirms empirically for this project.

**Latency versus accuracy.** The approaches also differ in when they can answer. A URL model can respond before the page renders; a visual model needs the rendered page; a language-model pipeline needs a network round trip. Apruzzese et al. (2023) observe that deployed detectors are rarely a single model: they are pipelines in which inexpensive, precise checks run first and costly models are consulted only when needed. Table 2.5 summarises these trade-offs.

**Table 2.5: Architectural Trade-offs Between Phishing Detection Approaches**

| Approach (representative work) | Evidence examined | Principal strength | Principal weakness | Relative latency |
| --- | --- | --- | --- | --- |
| Blacklist (Google Safe Browsing; Oest et al., 2020) | Previously reported URL | Near-zero false positives; negligible cost | No protection in the first hours of a campaign | Lowest |
| URL-only neural model (Le et al., 2018; Maneriker et al., 2021) | Characters and subwords of the URL | Works before the page loads; no rendering | Blind to neutral or compromised hosts; benchmark scores inflated by random splits | Low |
| URL + HTML features (Aljofey et al., 2022) | URL, forms, links, text | Sees credential forms and page content | Needs the page; results sensitive to dataset construction | Medium |
| Reference-based vision (Lin et al., 2021; Liu et al., 2022) | Logo / layout versus domain | Direct test of brand impersonation; robust to text obfuscation | Fixed brand list; needs screenshot and GPU | High |
| LLM-assisted (Li et al., 2024; Liu et al., 2024; Koide et al., 2023) | Page text and brand knowledge of a language model | Open-ended brand coverage; more zero-day detections | Remote inference: cost, latency and privacy exposure | Highest |
| Deterministic registry lookup (this project) | Account numbers shown on the page | Certain for known accounts; explains itself | Only as good as the registry; no generalisation | Lowest |

#### 2.6.4 Research Gap Mapping and Justification of the Hybrid Architecture

Table 2.6 maps each gap identified in the literature to the evidence for it and to the design decision it motivates in PhishGuard-AI. The mapping makes the central argument of this chapter explicit: because every individual technique fails in a way that another technique detects, the system combines them and blocks a page only when independent signals corroborate one another. The exception is the registry lookup, which is a factual match rather than an inference.

**Table 2.6: Research Gap Mapping to PhishGuard-AI Design Decisions**

| # | Research gap | Evidence in the literature | Design decision in PhishGuard-AI | Where evaluated |
| --- | --- | --- | --- | --- |
| G1 | Reactive defences leave an exposure window at the start of a campaign | Oest et al. (2020): detection on average nine hours after the first victim | Every page is analysed at request time by the browser extension; no dependence on prior reports | Section 5.5.3 (latency) |
| G2 | URL-only models miss content cues and their benchmark accuracy overstates real performance | Arp et al. (2022); Dalton et al. (2025); Hannousse & Yahiouche (2021) | BERT is used as a supporting signal only; it never blocks without corroboration | Sections 5.5.1–5.5.2 (hold-out versus Malaysian benchmark; ablation) |
| G3 | Brand impersonation needs an explicit brand-to-domain check | Lin et al. (2021); Liu et al. (2022); Abdelnabi et al. (2020) | Brand profiler with three evidence tiers (brand in hostname, look-alike domain, text mention) plus the partner module's YOLOv8 logo detector | Section 5.5.2 (categories P1, P4) |
| G4 | No public Malaysian scam corpus in Bahasa Melayu or Manglish | Corpora surveyed are English-centric; Bitaab et al. (2023) for payment-diversion fraud | Multilingual scam lexicon and credential-form detection instead of a multilingual model; a 120-page Malaysian benchmark for evaluation | Section 5.5.2 (category P2) |
| G5 | No surveyed system verifies the beneficiary account shown on a page | None of the systems in Table 2.4 inspects account numbers | Regex extraction of Malaysian account formats with an indexed registry lookup and an analyst-reviewed report queue | Section 5.5.2 (category P3) |
| G6 | Powerful models are too slow, costly or privacy-invasive for per-page use | Apruzzese et al. (2023); Li et al. (2024); Liu et al. (2024) | Self-hosted pipeline; whitelist bypass and result cache before any model inference | Section 5.5.3; Section 6.2 |
| G7 | Single-signal detectors produce false alarms that users learn to ignore | Arp et al. (2022) on base-rate neglect | Corroborated verdict engine (rules R1–R6); measured false-positive rate reported alongside recall | Section 5.5.2 (baseline versus final) |

Two consequences follow for the remainder of this report. First, the architecture in Chapter 4 is organised around independent signal producers and a single decision component, rather than around one dominant model. Second, the evaluation in Chapter 5 reports the false-positive rate on legitimate Malaysian pages with the same prominence as detection accuracy, because gap G7 identifies false alarms as the failure that makes a protective tool unusable in practice.

### 2.7 Chapter Summary

This chapter has established the theoretical foundations, empirical threat context, and technological frameworks underpinning modern anti-phishing defence systems. The critical findings of this literature review are summarised as follows:

- **Failure of Reactive Defences**: Blacklists leave an exposure window at the start of every campaign. Oest et al. (2020) measured an average of nine hours between a campaign's first victim and its detection, in campaigns that were on average over within 21 hours.
- **Cognitive Vulnerability & Social Engineering**: Attackers systematically trigger human "System 1" emotional decision-making through urgency cues, bypassing logical verification and necessitating automated client-side protection.
- **Strengths and Limits of Transformer Models (BERT)**: Bidirectional self-attention with WordPiece tokenisation outperforms TF-IDF and LSTM baselines on in-distribution benchmarks, but published accuracy figures depend heavily on how the data is split and do not transfer automatically to new content.
- **Necessity of Localised Deterministic Fraud Verification**: Automated regular expression parsing coupled with a normalised SQLite 3NF database removes the manual step of checking an account on PDRM Semakmule, provided the registry is kept current.
- **High-Concurrency ASGI Backend Architecture**: Asynchronous microservices powered by FastAPI and Uvicorn resolve Python GIL bottlenecks by offloading PyTorch tensor calculations to dedicated worker threads (asyncio.to_thread) while executing database I/O concurrently (asyncio.gather), keeping the event loop responsive while a forward pass is running.
These insights, consolidated in the gap mapping of Table 2.6, directly inform the architectural design and experimental methodology of the PhishGuard-AI backend module. The next chapter **Chapter 3: Methodology and Requirements Analysis** formalises the research framework, functional and non-functional requirements, dataset engineering pipelines, and mathematical evaluation metrics used to develop the system.
