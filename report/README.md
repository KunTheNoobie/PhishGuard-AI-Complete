# PhishGuard-AI: Final Year Project Report & Dissertation

**Author**: Liew Yi Ler (Student ID: 25WMR09747)  
**Supervisor**: Dr. Ng Yen Phing  
**Faculty**: Faculty of Computing and Information Technology (FOCS)  
**Institution**: Tunku Abdul Rahman University of Management and Technology (TAR UMT)  
**Programme**: Bachelor of Information Technology (Honours) in Information Security  
**Academic Year**: 2026/2027  

---

## 📑 Complete Dissertation Document Structure

| Section / Chapter | Title & Contents | File Link | Status |
| :--- | :--- | :--- | :---: |
| **Front Matter & Chapter 1** | Cover Page, Declaration, Abstract, Acknowledgements, Table of Contents, Introduction | [`Chapter_1_Introduction.md`](Chapter_1_Introduction.md) | ✅ Complete |
| **Chapter 2** | Literature Review | [`Chapter_2_Literature_Review.md`](Chapter_2_Literature_Review.md) | ✅ Complete |
| **Chapter 3** | Methodology and Requirements Analysis | [`Chapter_3_Methodology.md`](Chapter_3_Methodology.md) | ✅ Complete |
| **Chapter 4** | System Design | [`Chapter_4_System_Design.md`](Chapter_4_System_Design.md) | ✅ Complete |
| **Chapter 5** | Implementation and Testing | [`Chapter_5_Implementation_Testing.md`](Chapter_5_Implementation_Testing.md) | ✅ Complete |
| **Chapter 6** | Discussions and Conclusion | [`Chapter_6_Discussion_Conclusion.md`](Chapter_6_Discussion_Conclusion.md) | ✅ Complete |
| **References** | Academic Bibliography (APA 7th Edition with DOIs and links) | [`References.md`](References.md) | ✅ Complete |
| **Appendices** | Captured API responses, verdict-engine excerpt, Pytest + coverage log (198/198), benchmark and Locust output, reproduction commands | [`Appendices.md`](Appendices.md) | ✅ Complete |

---

## 📊 Evaluation Figures (v3.2.0)

The quantitative figures in Chapters 4 and 5 are generated from committed result files by
`python -m evaluation.make_report_figures` and stored in [`figures/`](figures/):
sequence diagram (Figure 4.8), database schema (Figure 4.6), training loss (Figure 5.3),
hold-out confusion matrix (Figure 5.4), benchmark results (Figures 5.5–5.8) and load test (Figure 5.9).
Method, raw numbers and limitations: [`../evaluation/README.md`](../evaluation/README.md).

The Markdown chapters in this folder are generated from the Word report, which is the authoritative version.

---

## 🎨 PlantUML Architectural Diagrams

The PlantUML sources of the Project I architecture diagrams are kept in the [`diagrams/`](diagrams/) directory:

* [`Chapter_1_Diagrams.puml`](diagrams/Chapter_1_Diagrams.puml):
  - *Figure 1.1*: PhishGuard-AI High-Level System Architecture & Module Boundaries.
  - *Figure 1.2*: Asynchronous Multi-Modal Threat Interception Sequence Flow.
  - *Figure 1.3*: Hybrid Agile-MLOps Engineering Lifecycle Framework.
  - *Figure 1.4*: CIA Triad Vulnerability & Mitigation Model.
* [`Chapter_2_Diagrams.puml`](diagrams/Chapter_2_Diagrams.puml):
  - *Figure 2.1*: Human Cognitive Bias Exploitation vs. PhishGuard-AI Automated Interception (Kahneman Dual-Process Model).
  - *Figure 2.2*: Evolution of NLP Threat Detection Paradigms (TF-IDF $\rightarrow$ LSTM $\rightarrow$ BERT Self-Attention).
  - *Figure 2.3*: Synchronous WSGI Thread Starvation Bottleneck vs. Asynchronous ASGI Microservice Architecture.
  - *Figure 2.4*: PhishGuard-AI Zero-Trust Theoretical Conceptual Framework.
* [`Chapter_3_Diagrams.puml`](diagrams/Chapter_3_Diagrams.puml):
  - *Figure 3.1*: Agile-MLOps Hybrid Engineering Workflow & CI/CD Verification Pipeline.
  - *Figure 3.2*: Adversarial Misuse Case Tree & Defensive Countermeasures Model.
  - *Figure 3.3*: Data Science ETL, WordPiece Tokenization & Deep Learning Training Pipeline.
  - *Figure 3.4*: Confusion Matrix Mathematical Model & ROC-AUC Decision Boundary.
* [`Chapter_4_Diagrams.puml`](diagrams/Chapter_4_Diagrams.puml):
  - *Figure 4.1*: PhishGuard-AI Decoupled N-Tier Microservices Architecture.
  - *Figure 4.2*: UML Use Case Diagram (Browser Client, SOC Administrator, Law Enforcement).
  - *Figure 4.3*: UML Activity Diagram (Asynchronous Parallel Execution & Whitelist Bypass Flow).
  - *Figure 4.4*: UML Sequence Diagram (End-to-End Multi-Modal Threat Verification).
  - *Figure 4.5*: UML Class Diagram (Singleton Pattern, Pydantic DTOs, and Service Engines).
  - *Figure 4.6*: Database Entity-Relationship Diagram (3NF Schema & B-Tree Indexes).
  - *Figure 4.7*: Physical Deployment Topology & Network Infrastructure.
* [`Chapter_5_Diagrams.puml`](diagrams/Chapter_5_Diagrams.puml):
  - *Figure 5.1*: Data Preprocessing, Sanitization, and WordPiece Ingestion Pipeline.
  - *Figure 5.2 source*: BERT URL classifier hold-out confusion matrix (109,870 URLs; values from `evaluation/kaggle_holdout_metrics.py`).
  - *Latency source*: measured request flow and Locust results (v3.2.0).
  - *Test-suite source*: 198 tests, 77% coverage (v3.2.0).
* [`Chapter_6_Diagrams.puml`](diagrams/Chapter_6_Diagrams.puml):
  - *Figure 6.1*: Edge-Adjacent Self-Hosted Microservice vs. Third-Party Cloud AI Architecture.
  - *Figure 6.2*: Technical Challenge Root-Cause and Architectural Resolution Dependency Model.
  - *Figure 6.3*: Proposed Enterprise Cloud-Native Kubernetes & Automated MLOps Retraining Topology.
