-- findings
CREATE TABLE findings (
  id UUID PRIMARY KEY,
  canonical_id TEXT UNIQUE,
  title TEXT,
  description TEXT,
  severity TEXT,
  cvss NUMERIC,
  cwe INT,
  asset_id TEXT,
  first_seen TIMESTAMP,
  last_seen TIMESTAMP,
  canonical_fingerprint TEXT,
  confidence INT,
  occurrences INT DEFAULT 1,
  status TEXT DEFAULT 'open'
);

-- evidence
CREATE TABLE evidence (
  id SERIAL PRIMARY KEY,
  finding_id UUID REFERENCES findings(id),
  type TEXT,
  artifact_url TEXT,
  content TEXT
);

-- playbook_runs
CREATE TABLE playbook_runs (
  id UUID PRIMARY KEY,
  playbook_id TEXT,
  finding_id UUID,
  started_at TIMESTAMP,
  ended_at TIMESTAMP,
  status TEXT
);