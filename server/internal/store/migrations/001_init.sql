-- PostgreSQL core schema (PRD 6.1, 6.3). Columns beyond the PRD are the ones the console needs to render.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE sites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    domain_name VARCHAR(255) NOT NULL UNIQUE,
    paranoia_level INT NOT NULL DEFAULT 1 CHECK (paranoia_level BETWEEN 1 AND 4),
    inbound_threshold INT NOT NULL DEFAULT 5 CHECK (inbound_threshold BETWEEN 1 AND 100),
    outbound_threshold INT NOT NULL DEFAULT 4 CHECK (outbound_threshold BETWEEN 1 AND 100),
    crs_categories JSONB NOT NULL DEFAULT '{"913":true,"920":true,"921":true,"930":true,"931":true,"932":true,"933":true,"941":true,"942":true,"944":true,"950":true,"955":true}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_name VARCHAR(100) NOT NULL UNIQUE,
    hostname VARCHAR(255) NOT NULL DEFAULT '',
    ip_address VARCHAR(45) NOT NULL DEFAULT '',
    proxy VARCHAR(30) NOT NULL DEFAULT '',
    version VARCHAR(64) NOT NULL DEFAULT '',
    crs_version VARCHAR(64) NOT NULL DEFAULT '',
    region VARCHAR(64) NOT NULL DEFAULT '',
    lon DOUBLE PRECISION NOT NULL DEFAULT 0,
    lat DOUBLE PRECISION NOT NULL DEFAULT 0,
    current_config_version BIGINT NOT NULL DEFAULT 0,
    cpu REAL NOT NULL DEFAULT 0,
    memory REAL NOT NULL DEFAULT 0,
    rps REAL NOT NULL DEFAULT 0,
    latency_ms REAL NOT NULL DEFAULT 0,
    last_heartbeat TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE enrollment_tokens (
    token_hash BYTEA PRIMARY KEY,
    node_name VARCHAR(100) NOT NULL,
    created_by VARCHAR(100) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE TABLE custom_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id INT NOT NULL UNIQUE,
    site_id UUID REFERENCES sites(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    seclang_raw TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by VARCHAR(100) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE rule_exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    rule_id INT NOT NULL,
    path_pattern VARCHAR(255) NOT NULL,
    parameter_name VARCHAR(100),
    reason TEXT NOT NULL DEFAULT '',
    exception_rule_id INT NOT NULL UNIQUE, -- id of the generated SecRule (10000-19999)
    created_by VARCHAR(100) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ip_list (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cidr CIDR NOT NULL,
    list VARCHAR(5) NOT NULL CHECK (list IN ('block', 'allow')),
    source VARCHAR(100) NOT NULL DEFAULT 'manual',
    reason TEXT NOT NULL DEFAULT '-',
    expires_at TIMESTAMPTZ,
    created_by VARCHAR(100) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (cidr, list)
);

CREATE TABLE threat_feeds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    url TEXT NOT NULL,
    format VARCHAR(4) NOT NULL CHECK (format IN ('text', 'csv')),
    interval_minutes INT NOT NULL CHECK (interval_minutes BETWEEN 5 AND 10080),
    last_pulled TIMESTAMPTZ,
    entries INT NOT NULL DEFAULT 0,
    status VARCHAR(5) NOT NULL DEFAULT 'NEVER',
    error TEXT
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject TEXT NOT NULL UNIQUE,          -- "<issuer>|<sub>" from the ID token
    name VARCHAR(200) NOT NULL,
    email VARCHAR(320) NOT NULL UNIQUE,
    role VARCHAR(20) NOT NULL CHECK (role IN ('Admin', 'SecOps Analyst', 'Auditor')),
    mfa BOOLEAN NOT NULL DEFAULT FALSE,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    token_hash BYTEA PRIMARY KEY,          -- sha256 of the cookie value; the raw token is never stored
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- FR-5.2: append-only. The trigger below rejects UPDATE and DELETE.
CREATE TABLE audit_trail (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor VARCHAR(200) NOT NULL,
    role VARCHAR(20) NOT NULL,
    action VARCHAR(100) NOT NULL,
    target TEXT NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    target_nodes TEXT NOT NULL DEFAULT '-'
);
CREATE INDEX audit_trail_at ON audit_trail (at DESC);
CREATE FUNCTION audit_trail_immutable() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit_trail is append-only'; END $$ LANGUAGE plpgsql;
CREATE TRIGGER audit_trail_no_change BEFORE UPDATE OR DELETE ON audit_trail
    FOR EACH ROW EXECUTE FUNCTION audit_trail_immutable();

CREATE SEQUENCE campaign_seq;
CREATE TABLE attack_campaigns (
    id VARCHAR(40) PRIMARY KEY,
    actor_key VARCHAR(255) NOT NULL,
    actor_mode VARCHAR(20) NOT NULL DEFAULT 'IP',
    site_id UUID,
    country_code VARCHAR(2) NOT NULL DEFAULT 'ZZ',
    asn BIGINT NOT NULL DEFAULT 0,
    as_name VARCHAR(200) NOT NULL DEFAULT '',
    lon DOUBLE PRECISION NOT NULL DEFAULT 0,
    lat DOUBLE PRECISION NOT NULL DEFAULT 0,
    correlation_confidence VARCHAR(10) NOT NULL DEFAULT 'MEDIUM',
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    highest_stage VARCHAR(20) NOT NULL,
    stages TEXT[] NOT NULL DEFAULT '{}',
    categories TEXT[] NOT NULL DEFAULT '{}',
    targets TEXT[] NOT NULL DEFAULT '{}',
    shell_paths TEXT[] NOT NULL DEFAULT '{}',
    risk_score INT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    event_count BIGINT NOT NULL DEFAULT 0,
    possibly_successful BIGINT NOT NULL DEFAULT 0,
    opened BOOLEAN NOT NULL DEFAULT FALSE,  -- false until min_events_to_open is reached
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    assignee VARCHAR(100),
    notes JSONB NOT NULL DEFAULT '[]',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX attack_campaigns_last_seen ON attack_campaigns (last_seen DESC);

CREATE TABLE killchain_rule_mapping (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id_from INT NOT NULL,
    rule_id_to INT NOT NULL,
    tag VARCHAR(100),
    rule_category VARCHAR(30) NOT NULL,
    killchain_stage VARCHAR(20) NOT NULL,
    mitre_technique VARCHAR(20),
    UNIQUE (rule_id_from, rule_id_to),
    CHECK (rule_id_from <= rule_id_to)
);
INSERT INTO killchain_rule_mapping (rule_id_from, rule_id_to, tag, rule_category, killchain_stage, mitre_technique) VALUES
    (1000, 1999, 'ip-reputation', 'SCANNER', 'RECON', 'T1595'),
    (913000, 913999, 'attack-reputation-scanner', 'SCANNER', 'RECON', 'T1595.002'),
    (920000, 920999, 'attack-protocol', 'PROTOCOL', 'DELIVERY', 'T1190'),
    (921000, 921999, 'attack-protocol', 'PROTOCOL', 'DELIVERY', 'T1190'),
    (930000, 930999, 'attack-lfi', 'LFI', 'EXPLOIT', 'T1190'),
    (931000, 931999, 'attack-rfi', 'LFI', 'EXPLOIT', 'T1190'),
    (932000, 932999, 'attack-rce', 'RCE', 'EXPLOIT', 'T1059.004'),
    (933000, 933999, 'attack-injection-php', 'RCE', 'EXPLOIT', 'T1059'),
    (934000, 934999, 'attack-injection-generic', 'RCE', 'EXPLOIT', 'T1059'),
    (941000, 941999, 'attack-xss', 'XSS', 'EXPLOIT', 'T1059.007'),
    (942000, 942999, 'attack-sqli', 'SQLI', 'EXPLOIT', 'T1190'),
    (943000, 943999, 'attack-fixation', 'PROTOCOL', 'EXPLOIT', 'T1190'),
    (944000, 944999, 'attack-injection-java', 'RCE', 'EXPLOIT', 'T1059'),
    (950000, 954999, 'attack-disclosure', 'LEAKAGE', 'OBJECTIVES', 'T1041'),
    (955000, 955999, 'attack-webshell', 'RCE', 'INSTALL', 'T1505.003'),
    (900000, 909999, NULL, 'SQLI', 'EXPLOIT', 'T1190');

CREATE TABLE correlation_settings (
    site_id UUID PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    actor_key_mode VARCHAR(20) NOT NULL DEFAULT 'IP' CHECK (actor_key_mode IN ('IP', 'CIDR24', 'ASN', 'FINGERPRINT')),
    idle_timeout_minutes INT NOT NULL DEFAULT 30 CHECK (idle_timeout_minutes BETWEEN 1 AND 1440),
    min_events_to_open INT NOT NULL DEFAULT 3 CHECK (min_events_to_open BETWEEN 1 AND 1000)
);

-- Deployed config bundles. The highest version is what nodes must run; dirty = policy changed since that deploy.
CREATE TABLE config_versions (
    version BIGSERIAL PRIMARY KEY,
    bundle JSONB NOT NULL,
    created_by VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE config_state (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    dirty BOOLEAN NOT NULL DEFAULT FALSE
);
INSERT INTO config_state DEFAULT VALUES;

-- Operator-defined network locations, checked before the MaxMind database (FR-6.1 enrichment).
CREATE TABLE geoip_overrides (
    cidr CIDR PRIMARY KEY,
    country_code VARCHAR(2) NOT NULL,
    asn BIGINT NOT NULL DEFAULT 0,
    as_name VARCHAR(200) NOT NULL DEFAULT '',
    lon DOUBLE PRECISION NOT NULL,
    lat DOUBLE PRECISION NOT NULL
);

-- CA that signs node certificates (NFR-2.1 mTLS).
CREATE TABLE pki (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    ca_cert_pem TEXT NOT NULL,
    ca_key_pem TEXT NOT NULL
);
