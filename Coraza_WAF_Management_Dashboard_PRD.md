# Product Requirement Document (PRD)
## Project: Coraza Management Dashboard & Control Plane (Coraza Console)

---

| Metadata | Details |
| :--- | :--- |
| **Document Version** | 1.1.0 (added Module 6: Dynamic Attack Mapping & Cyber Kill Chain Visualization) |
| **Status** | Draft / Proposed |
| **Author** | Security Engineering & SecOps Team |
| **Target Audience** | Core Developers, SecOps Team, Infrastructure/DevOps Engineers |
| **Core Engine** | OWASP Coraza WAF Engine (v3.x+) |

---

### 1. Executive Summary & Vision

#### 1.1 Problem Statement
OWASP Coraza adalah *enterprise-grade*, *open-source Web Application Firewall* (WAF) engine berbasis Go yang sangat fleksibel dan dapat diintegrasikan dengan berbagai reverse proxy (Caddy, Envoy, NGINX via Coraza-SPOA). Namun, Coraza tidak memiliki *out-of-the-box* Central Management Console / UI. Mengelola aturan SecLang, *false positive exclusions*, dan *audit logs* di banyak node Coraza secara manual melalui *config files* sangat rentan kesalahan, lambat, dan tidak memiliki visibilitas terpusat.

#### 1.2 Product Vision
Membangun **Coraza Console** — platform *Control Plane* dan *Observability Hub* terpusat, modern, dan scalable berbasis web. Coraza Console memungkinkan tim SecOps dan DevOps untuk:
- Mengelola kebijakan keamanan (*security policies*) dan *OWASP Core Rule Set* (CRS v4) secara terpusat.
- Melakukan pembaruan aturan secara *real-time* ke ribuan *edge node* tanpa *downtime* (*zero-downtime hot-reload* via gRPC).
- Mendapatkan visibilitas *real-time attack monitoring* dan *forensic logging* dengan *high-throughput time-series analytics* berbasis ClickHouse.
- Menyediakan alur *False Positive Resolution* dalam satu klik (*one-click exclusion*).
- Memvisualisasikan alur serangan secara interaktif dan *real-time* (**Dynamic Attack Mapping & Cyber Kill Chain Visualization**): event WAF dikorelasikan menjadi *attack campaign* dan dipetakan ke tahapan kill chain, sehingga analis melihat *siapa menyerang apa, dengan urutan bagaimana, dan sudah sampai tahap mana*, bukan sekadar angka statistik.

---

### 2. High-Level Architecture

```
                                +---------------------------+
                                |  Next.js / Shadcn UI      |
                                |  (Coraza Console Web UI)  |
                                +-------------+-------------+
                                              | REST / WebSockets
                                              v
                                +---------------------------+
                                |  Go Control Plane API     |
                                |  (Core Backend Engine)    |
                                +-----+---------------+-----+
                                      |               |
               +----------------------+               +-----------------------+
               | gRPC Config Stream                           | Audit Stream (gRPC/HTTP)
               v                                              v
  +--------------------------+                   +--------------------------+
  |  Coraza Edge Node 1      |                   |  ClickHouse Cluster      |
  |  (Caddy / Envoy / SPOA)  |                   |  (High-Performance Logs) |
  +--------------------------+                   +--------------------------+
               |                                              ^
               | gRPC Config Stream                           | Audit Stream
               v                                              |
  +--------------------------+                                |
  |  Coraza Edge Node N      |--------------------------------+
  |  (Caddy / Envoy / SPOA)  |
  +--------------------------+
```

#### 2.1 Component Description
1. **Frontend (Coraza UI):** Single Page Application berbasis Next.js 14, React, Tailwind CSS, dan Shadcn UI.
2. **Backend Control Plane:** Microservice berbasis Go (Fiber/Gin) yang menyediakan REST API untuk UI, mengelola state database, serta menyediakan gRPC Server untuk sinkronisasi agen/node.
3. **Database Stack:**
   - **PostgreSQL 16:** Menyimpan data terstruktur (User management, Roles/RBAC, Site/VHost configurations, SecLang Rules, Exception lists, Audit Trails).
   - **ClickHouse:** Menyimpan high-volume WAF Audit Logs (HTTP request headers, response codes, triggered Rule IDs, URI parameters, client IPs).
4. **Agent Integration (Coraza Enforcer Node):** Runtime Agent (Go plugin/sidecar) yang ditempatkan bersama Coraza Engine di Caddy/Envoy/SPOA untuk menerima pembaruan aturan via gRPC secara stream.
5. **Attack Correlation Engine (di dalam Control Plane):** Worker Go yang mengonsumsi audit stream, melakukan *enrichment* (GeoIP/ASN, mapping rule → kill chain stage), mengorelasikan event menjadi *attack campaign*, lalu mem-broadcast update graf ke UI via WebSocket. Berjalan sepenuhnya di Control Plane sehingga tidak menambah beban data plane.

---

### 3. User Personas & Target Roles

| Persona | Role | Primary Goals | Key Pain Points |
| :--- | :--- | :--- | :--- |
| **Ahmad (SecOps Analyst)** | Security Operations | Monitoring serangan real-time, triage incident, tuning *false positive*, mematikan rule ID spesifik per endpoint. | Sulit membaca *raw logs* di server log lokal, mematikan rule butuh edit file manual dan restart proxy. |
| **Budi (Cyber Security Engineer)** | Security Architecture | Membuat custom rule (SecLang), mengonfigurasi Paranoia Level OWASP CRS, integrasi SIEM/Alerting. | Sintaks SecLang rumit tanpa syntax validation, takut *rule update* merusak trafik produksi. |
| **Deni (DevOps / Infrastructure)** | Infra Engine | Management node health, deployment cluster WAF, memastikan *overhead latency* WAF < 2ms. | Tidak ada visibilitas resource usage WAF node secara terpusat. |

---

### 4. Detailed Feature Specifications

#### 4.1 Module 1: Fleet Management & Node Control Plane

##### Functional Requirements
- **FR-1.1 (Node Discovery & Heartbeat):** Node Coraza secara otomatis melakukan registrasi ke Control Plane via gRPC dengan `node_id`, `hostname`, `version`, dan `ip_address`.
- **FR-1.2 (Health & Performance Monitoring):** Menampilkan status node (*Healthy, Degraded, Unreachable*), CPU usage, Memory usage, Request Per Second (RPS), dan Average WAF Latency (ms).
- **FR-1.3 (Config Synchronization Status):** Menampilkan versi konfigurasi aktif pada setiap node (`sync_status: IN_SYNC` atau `PENDING_UPDATE`).

```
+------------------------------------------------------------------------------------------+
| FLEET MANAGEMENT                                                     [ + Register Node ] |
+------------------------------------------------------------------------------------------+
| NODE NAME         | HOSTNAME       | STATUS   | LATENCY | CRS VERSION | SYNC STATUS      |
+-------------------+----------------+----------+---------+-------------+------------------+
| edge-sg-caddy-01  | 10.10.1.15     | [ONLINE] | 1.2 ms  | CRS v4.0.0  | IN_SYNC (v104)   |
| edge-sg-envoy-02  | 10.10.1.16     | [ONLINE] | 1.8 ms  | CRS v4.0.0  | IN_SYNC (v104)   |
| edge-id-spoa-01   | 10.10.2.10     | [WARN]   | 8.5 ms  | CRS v3.3.4  | PENDING_UPDATE   |
+------------------------------------------------------------------------------------------+
```

---

#### 4.2 Module 2: OWASP CRS & SecLang Rule Management Engine

##### Functional Requirements
- **FR-2.1 (OWASP CRS v4 Visual Switch):** Mengaktifkan/nonaktifkan kategori CRS (misal: SQLi `942xxx`, XSS `941xxx`, RCE `932xxx`, Protocol Attack `920xxx`) dengan sakelar (*toggle switch*).
- **FR-2.2 (Paranoia Level & Anomaly Threshold Tuning):**
  - Slider visual untuk memilih **Paranoia Level (PL 1 - PL 4)** per site.
  - Form input **Inbound Anomaly Score Threshold** (default: 5) dan **Outbound Anomaly Score Threshold** (default: 4).
- **FR-2.3 (Visual Custom Rule Builder & Monaco Code Editor):**
  - **GUI Mode:** Form berbasis UI untuk membuat rule sederhana (Match Target, Operator, Action, Phase, Severity).
  - **Code Mode:** Embedded Monaco Editor (VS Code core) dengan *SecLang Syntax Highlighting*, auto-completion, dan *real-time linter* untuk mendeteksi kesalahan sintaks SecLang sebelum disimpan.
- **FR-2.4 (Testing Sandbox / Dry-Run Engine):**
  - Fitur pengujian payload terhadap aturan yang baru ditulis menggunakan engine Go FTW (Framework for Testing WAF).
  - Mengembalikan status: `MATCHED` / `PASSED` beserta Rule ID yang terpicu.

```
+------------------------------------------------------------------------------------------+
| RULE EDITOR: CUSTOM_SQLI_BYPASS_900001                                                  |
+------------------------------------------------------------------------------------------+
| Mode: [ Visual Builder | (X) Monaco SecLang Code Editor ]                                |
+------------------------------------------------------------------------------------------+
| 1 | SecRule ARGS:user_id "@rx (?i)(union\s+select|select\s+@@version)" \               |
| 2 |     "id:900001,\                                                                     |
| 3 |     phase:2,\                                                                        |
| 4 |     deny,\                                                                           |
| 5 |     status:403,\                                                                     |
| 6 |     msg:'Custom SQL Injection Pattern Detected',\                                    |
| 7 |     logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}',\               |
| 8 |     tag:'application-multi',\                                                        |
| 9 |     severity:'CRITICAL'"                                                             |
+------------------------------------------------------------------------------------------+
| Status: Syntax Validated (0 Errors, 0 Warnings)                 [ Test Sandbox ] [ Save ]|
+------------------------------------------------------------------------------------------+
```

---

#### 4.3 Module 3: Incident Forensic Explorer & False Positive Tuning

##### Functional Requirements
- **FR-3.1 (High-Speed Log Explorer):** Integrasi langsung ke ClickHouse. Mampu memfilter millions of log dalam hitungan milidetik berdasarkan:
  - Time Range, Client IP, Target Host, URI Path, Matched Rule ID, Action Taken (`DENY`, `LOG`, `ALLOW`), HTTP Status Code.
- **FR-3.2 (Transaction Detail Inspector):** Menampilkan detail lengkap transaksi HTTP:
  - Header Request & Body Payload.
  - Matched Variable Name & Matched Data String.
  - Matched Rule Metadatas (Rule ID, Message, Severity, Tag).
- **FR-3.3 (One-Click Exception / Rule Suppression):**
  - Tombol **"Disable Rule for this Endpoint"** pada log detail.
  - Sistem otomatis menyusun rule `SecRuleUpdateTargetById` atau `ctl:ruleRemoveById` tanpa menulis manual.

```
+------------------------------------------------------------------------------------------+
| LOG EXPLORER                                                          [ Live Stream: ON ]|
+------------------------------------------------------------------------------------------+
| Filter: [ Rule ID: 942100  x ] [ Action: DENY  x ] [ Target: api.domain.com  x ]        |
+------------------------------------------------------------------------------------------+
| TIMESTAMP           | CLIENT IP       | METHOD | URI PATH         | RULE ID | ACTION     |
+---------------------+-----------------+--------+------------------+---------+------------+
| 2026-08-24 19:40:12 | 185.220.101.5   | POST   | /api/v1/login    | 942100  | DENY (403) |
| 2026-08-24 19:39:55 | 103.21.244.12   | GET    | /products/search | 941100  | DENY (403) |
+------------------------------------------------------------------------------------------+

DETAIL VIEW (Log ID: log_908123491)
--------------------------------------------------------------------------------------------
Client IP    : 185.220.101.5 (Country: RU / AS13335)
Matched Rule : 942100 (SQL Injection Attack Detected via libinjection)
Matched Var  : ARGS:username = ' OR '1'='1
Action Taken : Blocked (HTTP 403)

[ Create Exception / Allow Rule for /api/v1/login ]  [ Add IP to Blacklist ]
```

---

#### 4.4 Module 4: Analytics, Dashboarding & Threat Intelligence

##### Functional Requirements
- **FR-4.1 (Real-Time Attack Dashboard):**
  - KPI Cards: Total Traffic (Req/s), Total Blocked Requests, Block Ratio (%), Average Latency Overhead.
  - Chart 1: Traffic vs Attack Trend (Line Chart Time-series).
  - Chart 2: Top 10 Triggered OWASP Rules (Bar Chart).
  - Chart 3: Top Targeted Endpoints & Top Attacking IPs (Table/Geo Map).
- **FR-4.2 (IP Reputation & Threat Feeds):**
  - Fitur **IP Allowlist & Blocklist** terpusat dengan dukungan CIDR (`192.168.1.0/24`).
  - Impor *Threat Intelligence Feed* otomatis via URL (format plain text/CSV).

---

#### 4.5 Module 5: RBAC, Auditability & GitOps Integration

##### Functional Requirements
- **FR-5.1 (Role-Based Access Control):**
  - `Admin`: Full access (System settings, User management, Policy creation/push).
  - `SecOps Analyst`: View logs, triage incidents, create exception requests, write draft rules.
  - `Auditor`: Read-only access ke dashboard analytics dan audit logs.
- **FR-5.2 (Audit Logging System):**
  - Semua aksi perubahan konfigurasi (*Rule added, Rule disabled, Policy deployed*) dicatat di PostgreSQL secara immutable (Siapa, Kapan, Aksi, IP Asal, IP Node Target).
- **FR-5.3 (GitOps / Config Export-Import):**
  - Ekspor seluruh WAF Policy ke format deklaratif `coraza-policy.yaml`.
  - Dukungan integrasi CI/CD pipeline (GitHub Actions/GitLab CI) untuk validasi rule via CLI.

---

#### 4.6 Module 6: Dynamic Attack Mapping & Cyber Kill Chain Visualization

Modul ini **bukan** tambahan grafik statistik. Ini adalah *investigation workspace* visual: event Coraza WAF dikorelasikan menjadi **Attack Campaign**, digambar sebagai **graf relasi interaktif** (penyerang → target → endpoint → rule), diurutkan pada **timeline**, dan dipetakan ke tahapan **Cyber Kill Chain** secara *real-time*. Analis dapat mengklik node/edge, melakukan pivot ke Log Explorer, dan langsung mengambil tindakan (block, exception, export) dari graf.

##### 4.6.1 Konsep Inti

| Konsep | Definisi |
| :--- | :--- |
| **Attack Event** | Satu transaksi HTTP yang memicu ≥1 rule Coraza (sumber: `coraza_audit_logs`), diperkaya GeoIP, ASN, kategori rule, dan kill chain stage. |
| **Attack Campaign** | Kumpulan Attack Event yang dikorelasikan menjadi satu rangkaian serangan oleh aktor yang sama (lihat FR-6.2). |
| **Kill Chain Stage** | Tahap serangan hasil mapping rule/tag Coraza (lihat 4.6.2). |
| **Attack Graph** | Graf node/edge dari satu atau banyak campaign untuk eksplorasi visual. |

##### 4.6.2 Kill Chain Mapping (WAF-Observable)

WAF hanya melihat lapisan HTTP, sehingga model Lockheed Martin Cyber Kill Chain disesuaikan. Tahap yang tidak dapat diamati WAF (*Weaponization*) ditandai eksplisit dan tidak digambar sebagai fakta. Setiap stage juga membawa referensi teknik **MITRE ATT&CK** untuk integrasi SIEM.

| Stage | Contoh Sinyal Coraza / CRS | Referensi ATT&CK |
| :--- | :--- | :--- |
| **1. Reconnaissance** | Scanner/crawler UA (`913xxx`), enumerasi path (404/403 beruntun), probing `/.git`, `/.env`, `/admin` | T1595 Active Scanning |
| **2. Weaponization** | *Tidak dapat diamati WAF* (ditampilkan sebagai stage abu-abu "Not observable") | - |
| **3. Delivery** | Protocol violation/evasion (`920xxx`), HTTP smuggling (`921xxx`), request anomali | T1190 Exploit Public-Facing App |
| **4. Exploitation** | SQLi `942xxx`, XSS `941xxx`, RCE `932xxx`, LFI/RFI `930xxx`/`931xxx`, PHP/Java injection `933xxx`/`944xxx` | T1190, T1059 |
| **5. Installation** | Upload webshell, akses file hasil upload mencurigakan, response berisi webshell signature (`955xxx`) | T1505.003 Web Shell |
| **6. Command & Control** | Request berulang ke endpoint webshell/backdoor, pola beaconing (interval teratur) dari IP yang sama | T1071 Application Layer Protocol |
| **7. Actions on Objectives** | Data leakage outbound (`950xxx`-`954xxx`), dump data besar, error SQL pada response | T1041 Exfiltration, T1530 |

Mapping disimpan sebagai tabel konfigurasi (`killchain_rule_mapping`, lihat 6.3) dan dapat di-*override* oleh Admin untuk custom rule (`9xxxxx`) maupun tag CRS.

##### 4.6.3 Functional Requirements

**A. Attack Correlation Engine**
- **FR-6.1 (Event Enrichment):** Setiap event diperkaya dengan Country/ASN/Geo-koordinat, kategori rule (dari tag `attack-*` / `OWASP_CRS`), kill chain stage, dan severity. Enrichment dilakukan di Control Plane, bukan di edge node.
- **FR-6.2 (Campaign Correlation):** Event dikelompokkan ke satu campaign berdasarkan aturan yang dapat dikonfigurasi:
  - Kunci aktor: `client_ip` (default), opsional digabung per `/24`, ASN, atau fingerprint (`User-Agent` + TLS/JA3 bila tersedia dari proxy).
  - *Sliding window* idle-timeout (default 30 menit): event baru dalam jendela waktu bergabung ke campaign aktif; di luar jendela membuat campaign baru.
  - Campaign mencatat: stage tertinggi yang dicapai, jumlah event, target (site/endpoint), rule terpicu, dan status (`ACTIVE`, `CONTAINED`, `CLOSED`).
- **FR-6.3 (Progression Detection & Alerting):** Sistem mendeteksi eskalasi stage (misal Reconnaissance → Exploitation dari aktor yang sama) dan menaikkan **Campaign Risk Score** (0–100) berdasarkan stage, jumlah target berbeda, variasi kategori serangan, dan keberhasilan (response 2xx setelah payload). Eskalasi memicu notifikasi (Webhook/Slack/Email/SIEM).
- **FR-6.4 (Outcome Classification):** Tiap event diberi hasil: `BLOCKED` (DENY), `DETECTED` (LOG only), atau `POSSIBLY_SUCCESSFUL` (payload terdeteksi tetapi request lolos dengan 2xx). Kategori `POSSIBLY_SUCCESSFUL` ditonjolkan sebagai prioritas triage.

**B. Dynamic Attack Graph (Interaktif)**
- **FR-6.5 (Graph Model):**
  - Node: `Attacker IP`, `ASN/Country` (opsional cluster), `Target Site`, `Endpoint/URI`, `Rule Category`, `Edge Node`.
  - Edge: request yang berarti (berlabel jumlah, rule, stage), arah panah dari penyerang ke target, ketebalan = volume, warna = stage/severity.
  - Warna node berdasarkan severity/stage, ikon berdasarkan tipe, ukuran berdasarkan jumlah event.
- **FR-6.6 (Real-Time Update):** Node dan edge baru muncul dengan animasi, edge aktif berkedip/mengalir; *playback controls* (Live / Pause / Replay). Latensi event → tampil di UI `< 2 detik`.
- **FR-6.7 (Interaksi):** Zoom/pan, drag node, *expand neighbors* (klik dua kali), *collapse/aggregate* (misal 500 IP dari satu ASN menjadi satu cluster), pencarian node, pin node, dan highlight jalur serangan (*path highlighting*) dari IP penyerang sampai endpoint target.
- **FR-6.8 (Filter & Layout):** Filter berdasarkan Time Range, Site, Kill Chain Stage, Severity, Rule Category, Outcome, dan Min Risk Score. Pilihan layout: *force-directed*, *hierarchical (left→right per stage)*, dan *radial*.
- **FR-6.9 (Node Limit & Aggregation):** Batas default 50 node per request ("Max nodes per-request") yang dapat diubah hingga 5.000; node di atas batas otomatis diagregasi agar UI tetap responsif.

**C. Kill Chain Visualization**
- **FR-6.10 (Kill Chain Progress Bar):** Pada setiap campaign tampil pipeline 7 stage; stage yang telah dicapai menyala, stage tertinggi ditandai, stage *Not observable* berwarna abu-abu. Klik stage memfilter graf dan timeline.
- **FR-6.11 (Attack Timeline):** Timeline horizontal dengan satu *swim-lane* per aktor atau per target, menampilkan event/bar sesuai stage dan waktu; histogram severity di atasnya; zoom (`1m`, `6m`, `1h`, `24h`, `7d`, custom) dan sinkron dengan graf (pilih event di timeline → highlight node/edge di graf, dan sebaliknya).
- **FR-6.12 (Campaign Radar):** Radar chart per campaign untuk profil serangan (SQLi, XSS, RCE, LFI, Scanner, Protocol, Leakage) sehingga karakter aktor terbaca sekilas.

**D. Dynamic Attack Map (Geo)**
- **FR-6.13 (Geo Attack Map):** Peta dunia/globe dengan *animated arc* dari negara/koordinat asal ke lokasi Edge Node target secara real-time; warna arc mengikuti stage/severity; klik negara/arc membuka daftar campaign terkait. Mode *Live Feed* dan *Heatmap*.

**E. Investigation & Response dari Graf**
- **FR-6.14 (Context Panel):** Klik node/edge membuka panel informasi: metadata IP (Geo/ASN/reputation, status block-list), ringkasan campaign, daftar event, rule terpicu, dan tombol *Open in Log Explorer* (pivot dengan filter otomatis).
- **FR-6.15 (Response Actions):** Dari node/campaign: **Block IP / CIDR** (ke Blocklist Module 4.4, dengan TTL), **Create Exception** (ke FR-3.3), **Mark as False Positive**, **Assign & Add Note**, **Close Campaign**. Semua aksi melewati RBAC dan tercatat pada Audit Log (FR-5.2); aksi *Block* menampilkan konfirmasi dan dampak (jumlah request sah yang pernah dari IP tersebut).
- **FR-6.16 (Export & Share):** Ekspor campaign sebagai JSON (STIX 2.1 bundle opsional), PNG/SVG graf, dan *Incident Report* (PDF) berisi timeline, kill chain, dan bukti event; *deep-link* ke campaign/graf yang sedang dilihat.
- **FR-6.17 (Replay):** Putar ulang campaign historis pada timeline untuk *post-incident review*.

##### 4.6.4 Wireframe

```
+----------------------------------------------------------------------------------------------------+
| ATTACK MAP & KILL CHAIN        [Live ON] [Site: all] [Stage: all] [Risk >= 40] [Layout: Force]      |
+----------------------------------------------------------------------------------------------------+
| Tabs: [Attack Graph] [Geo Map] [Campaign List] [Kill Chain Matrix]                                  |
+--------------------------------------------------------------+-------------------------------------+
|                                                              | CAMPAIGN  cmp_20260824_0192         |
|   (RU) 185.220.101.5 ==POST /login [942100 x38]==> api.domain|  Risk: 87 / 100      Status: ACTIVE |
|        |                                           |         |  Actor: 185.220.101.5 (AS13335, RU) |
|        +--GET /.env [913100]--> /.env              +--> /api |  Outcome: 2 POSSIBLY_SUCCESSFUL     |
|                                                              |                                     |
|   (CN) 103.21.244.12 --GET /search [941100 x7]--> shop.domain+-------------------------------------+
|                                                              | KILL CHAIN                          |
|   Legend: edge width = volume, color = stage                 | [Recon]>[Weapon]>[Deliv]>[Exploit]  |
|                                                              |  done    n/a     done     (CURRENT)  |
|                                                              |  >[Install]>[C2]>[Objectives]       |
|                                                              |   -         -     -                 |
+--------------------------------------------------------------+-------------------------------------+
| TIMELINE  [1m][6m][1h][24h][7d]                              | RADAR  SQLi ##### XSS ## RCE #      |
| 185.220.101.5 |--R--|----D----|====E=======E==E====          | ACTIONS                             |
| 103.21.244.12 |            |--E--E-----                      | [Block IP] [Exception] [Open Logs]  |
|               19:30     19:40     19:50     20:00            | [Assign] [Export STIX] [Close]      |
+--------------------------------------------------------------+-------------------------------------+
```

##### 4.6.5 Kebutuhan Teknis Spesifik Modul

- **Pipeline:** Audit stream → Attack Correlation Engine (stateful, windowed) → (a) tulis `attack_events`/`attack_campaigns`, (b) publish update delta via WebSocket ke UI yang berlangganan filter tertentu. State campaign aktif disimpan di Redis (atau in-memory dengan snapshot) agar Control Plane tetap *horizontally scalable* (NFR-3.2).
- **Frontend:** Rendering graf berbasis WebGL (Sigma.js/Cytoscape.js WebGL atau deck.gl untuk peta), layout dijalankan di Web Worker; komponen timeline dan radar menggunakan pustaka chart yang sudah dipakai Dashboard.
- **Akses & Privasi:** `Admin` dan `SecOps Analyst` dapat menjalankan response action; `Auditor` read-only (tanpa tombol aksi). Data payload pada panel detail mengikuti aturan *masking* NFR-2.3.
- **Degradasi aman:** Jika Correlation Engine atau WebSocket gagal, Log Explorer dan enforcement di edge node tetap berjalan normal (tidak ada dependensi data plane).
- **Keterbatasan yang dinyatakan di UI:** Kill chain bersifat *inferensi dari sinyal HTTP*; tahap `Weaponization` tidak diamati, dan korelasi per IP dapat keliru pada NAT/proxy bersama. UI menampilkan *confidence* korelasi (`HIGH`/`MEDIUM`/`LOW`).

---

### 5. Technical Requirements & Non-Functional Requirements (NFR)

#### 5.1 Performance Requirements
- **NFR-1.1 (Latency Overhead):** Control Plane tidak boleh membebani data plane Coraza node. Proses evaluasi rule di WAF node harus tetap `< 2ms` per request.
- **NFR-1.2 (Config Push Speed):** Distribusi konfigurasi baru dari Control Plane ke 100+ node Coraza via gRPC stream harus selesai dalam waktu `< 1 detik`.
- **NFR-1.3 (Log Ingestion Throughput):** ClickHouse cluster backend harus mampu menangani *ingestion rate* minimal **10.000 log/detik** tanpa data loss.
- **NFR-1.4 (Attack Visualization Performance):** Correlation Engine memproses ≥ 10.000 event/detik (sejalan NFR-1.3); latensi event → tampil di graf `< 2 detik`; Attack Graph tetap ≥ 30 FPS pada 5.000 node/edge terlihat (WebGL + agregasi); query campaign list `< 500 ms` untuk 30 hari data.

#### 5.2 Security Requirements
- **NFR-2.1 (Transport Security):** Komunikasi gRPC antara Control Plane dan Coraza Node WAJIB menggunakan **mTLS (Mutual TLS)** dengan Sertifikat x509.
- **NFR-2.2 (Authentication & Session):** Web Dashboard menggunakan OAuth2 / OpenID Connect (OIDC) dengan SSO (Keycloak, Okta, Google Workspace) & mandatory MFA.
- **NFR-2.3 (Data Retention & Privacy):**
  - Fitur *Masking Payload* sensitif (misal: header `Authorization`, cookie `session_id`, field `password`) sebelum disimpan ke ClickHouse log database.

#### 5.3 Reliability & High Availability
- **NFR-3.1 (Fail-Safe Node Operation):** Jika Control Plane down/unreachable, Coraza Edge Node harus tetap berjalan menggunakan *cached configuration* terakhir tanpa menghentikan inspeksi trafik.
- **NFR-3.2 (Stateless Control Plane):** API Control Plane dikembangkan secara stateless dalam Docker Container / Kubernetes Pod sehingga mudah di-scale horizontally.

---

### 6. Data Schema Specifications

#### 6.1 Relational Schema (PostgreSQL Core)

```sql
-- Sites / Virtual Hosts
CREATE TABLE sites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    domain_name VARCHAR(255) NOT NULL UNIQUE,
    paranoia_level INT DEFAULT 1 CHECK (paranoia_level BETWEEN 1 AND 4),
    inbound_threshold INT DEFAULT 5,
    outbound_threshold INT DEFAULT 4,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Coraza Nodes Fleet
CREATE TABLE nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_name VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    status VARCHAR(20) DEFAULT 'OFFLINE',
    current_config_version VARCHAR(64),
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Custom SecLang Rules
CREATE TABLE custom_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id INT NOT NULL UNIQUE,
    site_id UUID REFERENCES sites(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    seclang_raw TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Exceptions / Suppressions
CREATE TABLE rule_exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id UUID REFERENCES sites(id) ON DELETE CASCADE,
    rule_id INT NOT NULL,
    path_pattern VARCHAR(255) NOT NULL, -- e.g. /api/v1/upload
    parameter_name VARCHAR(100),       -- e.g. ARGS:file_description
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

#### 6.2 Analytics Schema (ClickHouse Audit Log)

```sql
CREATE TABLE coraza_audit_logs (
    timestamp DateTime64(3, 'UTC'),
    transaction_id String,
    node_id UUID,
    site_id UUID,
    client_ip String,
    client_port UInt16,
    http_method LowCardinality(String),
    uri String,
    http_version String,
    response_status UInt16,
    action_taken LowCardinality(String), -- 'DENY', 'LOG', 'ALLOW'
    matched_rule_ids Array(UInt32),
    matched_messages Array(String),
    matched_data Array(String),
    request_headers Map(String, String),
    request_body String,
    latency_us UInt64
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, site_id, action_taken, client_ip);
```

#### 6.3 Attack Mapping & Kill Chain Schema (Module 6)

```sql
-- ClickHouse: event yang sudah diperkaya & dikorelasikan (diisi Correlation Engine)
CREATE TABLE attack_events (
    timestamp DateTime64(3, 'UTC'),
    transaction_id String,            -- relasi ke coraza_audit_logs
    campaign_id UUID,
    node_id UUID,
    site_id UUID,
    client_ip String,
    country_code LowCardinality(String),
    asn UInt32,
    geo_lat Float32,
    geo_lon Float32,
    uri String,
    rule_id UInt32,
    rule_category LowCardinality(String),   -- 'SQLI','XSS','RCE','LFI','SCANNER','PROTOCOL','LEAKAGE'
    killchain_stage LowCardinality(String), -- 'RECON','DELIVERY','EXPLOIT','INSTALL','C2','OBJECTIVES'
    severity LowCardinality(String),
    outcome LowCardinality(String),         -- 'BLOCKED','DETECTED','POSSIBLY_SUCCESSFUL'
    response_status UInt16
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (campaign_id, timestamp);
```

```sql
-- PostgreSQL: metadata campaign (state investigasi oleh analis)
CREATE TABLE attack_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_key VARCHAR(255) NOT NULL,        -- IP / CIDR / ASN / fingerprint
    correlation_confidence VARCHAR(10) DEFAULT 'MEDIUM', -- HIGH | MEDIUM | LOW
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    highest_stage VARCHAR(20) NOT NULL,
    risk_score INT CHECK (risk_score BETWEEN 0 AND 100),
    event_count BIGINT DEFAULT 0,
    status VARCHAR(20) DEFAULT 'ACTIVE',    -- ACTIVE | CONTAINED | CLOSED | FALSE_POSITIVE
    assignee VARCHAR(100),
    notes TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Mapping rule/tag -> kill chain stage (dapat di-override Admin)
CREATE TABLE killchain_rule_mapping (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id_from INT NOT NULL,              -- mis. 942000
    rule_id_to INT NOT NULL,                -- mis. 942999
    tag VARCHAR(100),                       -- opsional: 'attack-sqli'
    rule_category VARCHAR(30) NOT NULL,
    killchain_stage VARCHAR(20) NOT NULL,
    mitre_technique VARCHAR(20),            -- mis. T1190
    UNIQUE (rule_id_from, rule_id_to)
);

-- Pengaturan korelasi per site
CREATE TABLE correlation_settings (
    site_id UUID PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    actor_key_mode VARCHAR(20) DEFAULT 'IP', -- IP | CIDR24 | ASN | FINGERPRINT
    idle_timeout_minutes INT DEFAULT 30,
    min_events_to_open INT DEFAULT 3
);
```

---

### 7. Success Metrics & Roadmap

#### 7.1 Key Performance Indicators (KPIs)
1. **MTTR (Mean Time to Resolution) for False Positives:** Berkurang dari 45 menit (manual edit & redeploy) menjadi `< 2 menit` (via Dashboard GUI Exception).
2. **Configuration Sync Latency:** `< 1 detik` untuk penyebaran rule baru ke seluruh infrastruktur.
3. **Dashboard Load Time:** Log Explorer mampu menampilkan query 1 juta data log dalam `< 500 ms`.
4. **MTTD (Mean Time to Detect) Multi-Stage Attack:** Eskalasi campaign (Recon → Exploitation) terdeteksi dan tampil di Attack Graph dalam `< 5 detik`; analis dapat menentukan stage dan target serangan dalam `< 1 menit` (vs. korelasi manual lintas log).
5. **Triage Efficiency:** ≥ 70% campaign ditangani (block/exception/close) langsung dari Attack Graph tanpa berpindah ke tool lain.

#### 7.2 Release Roadmap
- **Phase 1 (MVP - Month 1-2):**
  - Centralized Rule Editor (Monaco Editor) & Custom SecLang Builder.
  - Basic gRPC Agent Stream untuk dynamic config push ke Coraza-Caddy.
  - PostgreSQL schema implementation & Auth OIDC.
- **Phase 2 (Observability - Month 3-4):**
  - ClickHouse integration & High-performance Log Explorer.
  - Real-time Attack Analytics & OWASP Top 10 Metrics Dashboard.
  - One-Click Exception Generator.
  - **Module 6 (Part 1):** Event enrichment (GeoIP/ASN), kill chain mapping, Campaign Correlation Engine, Campaign List, Kill Chain Progress Bar, dan Geo Attack Map real-time.
- **Phase 3 (Enterprise Readiness - Month 5-6):**
  - GitOps Synchronization (GitHub/GitLab runner integration).
  - Automated Testing Sandbox via Go FTW.
  - Threat Intelligence Feed auto-pulling & RBAC fine-tuning.
  - **Module 6 (Part 2):** Interactive Attack Graph (WebGL) dengan timeline & radar tersinkron, response action dari graf, Campaign Replay, Risk Score & alerting eskalasi, ekspor STIX/PDF, dan integrasi MITRE ATT&CK.

---
