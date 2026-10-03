package database

// Schema DDL, hoisted out of CreateSchema so the names in it can be READ without
// executing it.
//
// SchemaReady needs to know which tables and indexes a current database is
// supposed to have, and the only trustworthy source for that is the same list
// CreateSchema applies. Keeping a second list beside it would drift on the first
// schema change and turn a missing table into a silently accepted one, which is
// exactly the failure the readiness check exists to prevent.
//
// Entries stay driver-neutral SQLite DDL; adaptDDL rewrites them for Postgres at
// execution time.

// schemaTables is every CREATE TABLE this binary expects, in dependency order.
var schemaTables = []string{
	// Schema versioning: lets CreateSchema skip one-time O(rows) backfills once
	// a database is current (see currentSchemaVersion). Single row, id always 1.
	`CREATE TABLE IF NOT EXISTS schema_meta (
		id INTEGER PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0
	)`,
	// Multi-tenancy: users and projects
	`CREATE TABLE IF NOT EXISTS users (
		uuid TEXT PRIMARY KEY NOT NULL,
		email TEXT,
		name TEXT,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS projects (
		uuid TEXT PRIMARY KEY NOT NULL,
		name TEXT NOT NULL,
		description TEXT,
		owner_uuid TEXT,
		config_path TEXT,
		tags TEXT,
		default_target TEXT,
		last_scan_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS scans (
		uuid TEXT PRIMARY KEY NOT NULL,
		project_uuid TEXT NOT NULL,
		name TEXT,
		description TEXT,
		status TEXT NOT NULL DEFAULT 'running',
		target TEXT,
		modules TEXT,
		threads INTEGER DEFAULT 0,
		scope_origin_mode TEXT,
		profile TEXT,
		source_path TEXT,
		source_type TEXT,
		tags TEXT,
		triggered_by TEXT,
		agentic_scan_uuid TEXT,
		http_record_uuid TEXT,
		scan_source TEXT,
		scan_mode TEXT,
		start_cursor_at TIMESTAMP,
		start_cursor_uuid TEXT,
		cursor_at TIMESTAMP,
		cursor_uuid TEXT,
		processed_count INTEGER DEFAULT 0,
		started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		finished_at TIMESTAMP,
		duration_ms INTEGER DEFAULT 0,
		total_requests INTEGER DEFAULT 0,
		total_findings INTEGER DEFAULT 0,
		critical_count INTEGER DEFAULT 0,
		high_count INTEGER DEFAULT 0,
		medium_count INTEGER DEFAULT 0,
		low_count INTEGER DEFAULT 0,
		info_count INTEGER DEFAULT 0,
		suspect_count INTEGER DEFAULT 0,
		error_message TEXT,
		storage_url TEXT,
		completeness TEXT,
		stop_reason TEXT,
		phase_outcomes TEXT,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS http_records (
		uuid TEXT PRIMARY KEY NOT NULL,
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT,
		scheme TEXT NOT NULL,
		hostname TEXT NOT NULL,
		port INTEGER NOT NULL,
		ip TEXT,
		method TEXT NOT NULL,
		path TEXT NOT NULL,
		url TEXT NOT NULL,
		http_version TEXT NOT NULL,
		request_content_type TEXT,
		request_content_length INTEGER DEFAULT 0,
		raw_request BLOB,
		request_hash TEXT NOT NULL,
		request_authorization TEXT,
		status_code INTEGER DEFAULT 0,
		status_phrase TEXT,
		response_http_version TEXT,
		response_content_type TEXT,
		response_content_length INTEGER DEFAULT 0,
		raw_response BLOB,
		response_hash TEXT,
		response_norm_hash TEXT,
		response_time_ms INTEGER DEFAULT 0,
		response_words INTEGER DEFAULT 0,
		has_response INTEGER NOT NULL DEFAULT 0,
		response_title TEXT,
		response_location TEXT,
		parameters TEXT,
		sent_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		received_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		source TEXT DEFAULT '',
		technology TEXT,
		content_hash TEXT,
		is_authenticated INTEGER NOT NULL DEFAULT 0,
		parent_uuid TEXT,
		target TEXT,
		root_uuid TEXT,
		chain_truncated INTEGER NOT NULL DEFAULT 0,
		remarks TEXT,
		risk_score INTEGER DEFAULT 0,
		surface_score INTEGER DEFAULT 0
	)`,
	`CREATE TABLE IF NOT EXISTS analysis_artifacts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT,
		http_record_uuid TEXT NOT NULL,
		kind TEXT NOT NULL,
		filename TEXT,
		media_type TEXT,
		sha256 TEXT NOT NULL,
		byte_length INTEGER NOT NULL,
		content BLOB NOT NULL,
		metadata TEXT,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_uuid TEXT NOT NULL,
		http_record_uuids TEXT NOT NULL,
		scan_uuid TEXT,
		agentic_scan_uuid TEXT,
		url TEXT,
		hostname TEXT,
		module_id TEXT NOT NULL,
		module_name TEXT NOT NULL,
		module_type TEXT DEFAULT '',
		finding_source TEXT DEFAULT '',
		record_kind TEXT NOT NULL DEFAULT 'finding',
		evidence_grade TEXT DEFAULT '',
		module_short TEXT DEFAULT '',
		description TEXT,
		severity TEXT NOT NULL,
		confidence TEXT NOT NULL DEFAULT 'firm',
		tags TEXT,
		status TEXT DEFAULT 'triaged',
		remediation TEXT,
		cwe_id TEXT,
		cvss_score REAL DEFAULT 0,
		source_file TEXT,
		repo_name TEXT,
		matched_at TEXT,
		extracted_results TEXT,
		additional_evidence TEXT,
		request TEXT,
		response TEXT,
		finding_hash TEXT NOT NULL,
		found_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS finding_records (
		finding_id INTEGER NOT NULL,
		record_uuid TEXT NOT NULL,
		PRIMARY KEY (finding_id, record_uuid)
	)`,
	`CREATE TABLE IF NOT EXISTS scopes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_uuid TEXT NOT NULL,
		name TEXT NOT NULL,
		description TEXT,
		rule_type TEXT NOT NULL,
		host_pattern TEXT,
		path_pattern TEXT,
		content_type_pattern TEXT,
		methods TEXT,
		ports TEXT,
		schemes TEXT,
		priority INTEGER NOT NULL DEFAULT 100,
		enabled INTEGER NOT NULL DEFAULT 1,
		hit_count INTEGER DEFAULT 0,
		last_matched_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS oast_interactions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT,
		unique_id TEXT NOT NULL,
		full_id TEXT NOT NULL,
		protocol TEXT NOT NULL,
		q_type TEXT,
		raw_request TEXT,
		raw_response TEXT,
		remote_address TEXT,
		interacted_at TIMESTAMP NOT NULL,
		target_url TEXT,
		parameter_name TEXT,
		injection_type TEXT,
		module_id TEXT,
		finding_id INTEGER,
		payload TEXT,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS agentic_scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		uuid TEXT NOT NULL UNIQUE,
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT,
		mode TEXT NOT NULL,
		agent_name TEXT NOT NULL,
		input_raw TEXT,
		input_type TEXT,
		target_url TEXT,
		vuln_type TEXT,
		module_names TEXT,
		template_id TEXT,
		status TEXT NOT NULL DEFAULT 'pending',
		current_phase TEXT,
		phases_run TEXT,
		finding_count INTEGER DEFAULT 0,
		record_count INTEGER DEFAULT 0,
		saved_count INTEGER DEFAULT 0,
		source_path TEXT,
		source_type TEXT,
		token_usage TEXT,
		retry_count INTEGER DEFAULT 0,
		parent_run_uuid TEXT,
		input_record_count INTEGER DEFAULT 0,
		attack_plan TEXT,
		triage_result TEXT,
		prompt_sent TEXT,
		agent_raw_output TEXT,
		error_message TEXT,
		result_json TEXT,
		storage_url TEXT,
		session_id TEXT,
		session_dir TEXT,
		started_at TIMESTAMP,
		completed_at TIMESTAMP,
		duration_ms INTEGER DEFAULT 0,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS authentication_hostnames (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT,
		hostname TEXT NOT NULL,
		session_name TEXT NOT NULL,
		session_role TEXT DEFAULT '',
		position INTEGER DEFAULT 0,
		session_token TEXT,
		headers TEXT,
		login_url TEXT,
		login_method TEXT,
		login_content_type TEXT,
		login_body TEXT,
		login_request TEXT,
		login_response TEXT,
		extract_rules TEXT,
		source TEXT DEFAULT '',
		hydrated_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	// One row per (run, endpoint): what this scan observed about a HOST, as
	// opposed to about one exchange with it.
	//
	// Normalized rather than stored on http_records. The per-row objection
	// that keeps the full DNS answer off the record still stands — a sweep
	// writes several rows per host and a redirect chain alone is three, so
	// columns would hold many identical copies of one answer — but it is an
	// argument against DUPLICATING the answer, not against keeping it. Here
	// it is written once per endpoint per run and referenced by hostname and
	// port.
	//
	// Keyed by scan_uuid so a re-probe RECORDS a new observation instead of
	// overwriting the old one: "what did the host resolve to when we scanned
	// it in March" is a question a report has to be able to answer, and an
	// upsert keyed on hostname alone would destroy the answer every time the
	// host was scanned again. UNIQUE(scan_uuid, hostname, port) makes a
	// repeat within ONE run idempotent, which is the only case where
	// overwriting is correct.
	//
	// complete distinguishes a lookup that ran and found nothing from one
	// that was cut short (a cancelled or budget-limited prefetch). Without
	// it an empty answer is unreadable: "this host has no AAAA record" and
	// "we never got to this host" are different facts about the scan.
	`CREATE TABLE IF NOT EXISTS host_observations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT,
		hostname TEXT NOT NULL,
		port INTEGER NOT NULL DEFAULT 0,
		observed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		dns_a TEXT,
		dns_aaaa TEXT,
		dns_cname TEXT,
		tls TEXT,
		complete INTEGER NOT NULL DEFAULT 0,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(scan_uuid, hostname, port)
	)`,
	`CREATE TABLE IF NOT EXISTS scan_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_uuid TEXT NOT NULL,
		scan_uuid TEXT NOT NULL,
		level TEXT NOT NULL,
		phase TEXT,
		message TEXT NOT NULL,
		metadata TEXT,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	// Durable autopilot: one row per bounded operator section (a Reset() +
	// reconstructed-brief cycle). Only written when autopilot_mode != legacy.
	`CREATE TABLE IF NOT EXISTS agent_sections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		uuid TEXT NOT NULL UNIQUE,
		agentic_scan_uuid TEXT,
		project_uuid TEXT,
		seq INTEGER NOT NULL DEFAULT 0,
		kind TEXT,
		status TEXT NOT NULL DEFAULT 'running',
		task TEXT,
		closing_summary TEXT,
		rotation_reason TEXT,
		turn_count INTEGER NOT NULL DEFAULT 0,
		input_tokens INTEGER NOT NULL DEFAULT 0,
		output_tokens INTEGER NOT NULL DEFAULT 0,
		error_message TEXT,
		started_at TIMESTAMP,
		ended_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	// Durable autopilot: verify-before-promote candidates. Each proposed
	// finding lands here first (status=proposed), a fresh-context verifier
	// grades it, and confirmed ones are promoted into findings. Only
	// written when autopilot_mode != legacy. UNIQUE(agentic_scan_uuid,
	// dedup_hash) backs the ON CONFLICT dedup on SaveCandidate.
	`CREATE TABLE IF NOT EXISTS agent_finding_candidates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		uuid TEXT NOT NULL UNIQUE,
		agentic_scan_uuid TEXT,
		project_uuid TEXT,
		section_uuid TEXT,
		title TEXT,
		severity TEXT,
		description TEXT,
		remediation TEXT,
		cwe_id TEXT,
		source_file TEXT,
		url TEXT,
		hostname TEXT,
		confidence TEXT,
		class TEXT,
		status TEXT NOT NULL DEFAULT 'proposed',
		verdict_reason TEXT,
		evidence_grade TEXT,
		record_uuids TEXT,
		oast_ids TEXT,
		request TEXT,
		response TEXT,
		dedup_hash TEXT NOT NULL DEFAULT '',
		promoted_finding_id INTEGER NOT NULL DEFAULT 0,
		tags TEXT,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		verified_at TIMESTAMP
	)`,
}

// schemaIndexes is every index this binary expects. Applied after the column
// migrations, since some of them reference columns added there.
var schemaIndexes = []string{
	"CREATE INDEX IF NOT EXISTS idx_analysis_artifacts_project_record ON analysis_artifacts(project_uuid, http_record_uuid)",
	"CREATE INDEX IF NOT EXISTS idx_analysis_artifacts_scan ON analysis_artifacts(scan_uuid)",
	"CREATE UNIQUE INDEX IF NOT EXISTS idx_analysis_artifacts_record_kind_hash ON analysis_artifacts(http_record_uuid, kind, sha256)",

	// -- host_observations --
	// The read is "what did this run see for this endpoint", issued once per
	// emitted record, so (project, scan, hostname, port) is the exact lookup.
	// The scan-less variant backs the fallback read for a caller that knows
	// the project but not which run to trust, which takes the most recent.
	// The only index this table needs beyond its UNIQUE(scan_uuid, hostname,
	// port) constraint. It covers the project-wide read - newest observation
	// for an endpoint, ORDER BY id DESC LIMIT 1 - with id in the index so the
	// lookup never fetches a table row per observation. The scan-scoped read
	// is served by the unique constraint's own index, so a third
	// (project_uuid, scan_uuid, hostname, port) index bought nothing and cost
	// a b-tree insertion on every observation written.
	"CREATE INDEX IF NOT EXISTS idx_host_obs_project_host_id ON host_observations(project_uuid, hostname, port, id)",

	// -- findings: project-aware composite indexes --
	"CREATE INDEX IF NOT EXISTS idx_findings_project_severity ON findings(project_uuid, severity)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_module ON findings(project_uuid, module_id)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_found_at ON findings(project_uuid, found_at)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_module_type ON findings(project_uuid, module_type)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_finding_source ON findings(project_uuid, finding_source)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_record_kind ON findings(project_uuid, record_kind)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_scan ON findings(project_uuid, scan_uuid)",
	// Covers aggregateScanFindings (SELECT severity, COUNT(*) WHERE scan_uuid = ?
	// GROUP BY severity), which runs on every scan-status tick. scan_uuid is not
	// the leading column of idx_findings_project_scan, so without this the count
	// fell back to a full findings scan each tick; (scan_uuid, severity) makes it
	// index-only.
	"CREATE INDEX IF NOT EXISTS idx_findings_scan_severity ON findings(scan_uuid, severity)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_status ON findings(project_uuid, status)",
	"CREATE INDEX IF NOT EXISTS idx_findings_project_hostname ON findings(project_uuid, hostname)",
	// Backs the per-round dynamic-assessment dedup grouping
	// (DeduplicateFindings / GroupFindingsByValue): the WHERE narrows on
	// (project_uuid, hostname) and the window function partitions by
	// (module_id, severity, …) ordered by created_at. Indexing all five lets
	// the host-scoped scan resolve from the index and arrive partially
	// pre-ordered for the PARTITION BY, instead of a full findings scan + sort
	// every feedback round. (matched_url is a json_extract expression and
	// stays per-row, but the module_id/severity prefix is satisfied here.)
	"CREATE INDEX IF NOT EXISTS idx_findings_project_host_module_sev ON findings(project_uuid, hostname, module_id, severity, created_at)",
	// Sparse (nullzero column) — used by agent end-of-run summaries and
	// webhook notifications to count findings per agentic-scan run.
	"CREATE INDEX IF NOT EXISTS idx_findings_agentic_scan ON findings(agentic_scan_uuid)",
	// Dedup is scoped per project: the same finding_hash may legitimately
	// recur across projects without one project's finding suppressing
	// another's. Backs ON CONFLICT (project_uuid, finding_hash).
	"CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_project_hash_unique ON findings(project_uuid, finding_hash)",

	// -- finding_records --
	"CREATE INDEX IF NOT EXISTS idx_finding_records_record_uuid ON finding_records(record_uuid)",
	"CREATE INDEX IF NOT EXISTS idx_finding_records_finding_id ON finding_records(finding_id)",

	// -- scans --
	"CREATE INDEX IF NOT EXISTS idx_scans_project_status ON scans(project_uuid, status)",
	"CREATE INDEX IF NOT EXISTS idx_scans_project_created ON scans(project_uuid, created_at)",

	// -- scopes --
	"CREATE INDEX IF NOT EXISTS idx_scopes_project_enabled_priority ON scopes(project_uuid, enabled, priority)",

	// -- oast_interactions --
	"CREATE INDEX IF NOT EXISTS idx_oast_project_scan ON oast_interactions(project_uuid, scan_uuid)",
	"CREATE INDEX IF NOT EXISTS idx_oast_interactions_unique_id ON oast_interactions(unique_id)",

	// -- agentic_scans --
	"CREATE INDEX IF NOT EXISTS idx_agentic_scans_uuid ON agentic_scans(uuid)",
	"CREATE INDEX IF NOT EXISTS idx_agentic_scans_project_status ON agentic_scans(project_uuid, status)",
	"CREATE INDEX IF NOT EXISTS idx_agentic_scans_project_created ON agentic_scans(project_uuid, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_agentic_scans_scan ON agentic_scans(scan_uuid)",

	// -- authentication_hostnames --
	"CREATE UNIQUE INDEX IF NOT EXISTS idx_authentication_hostnames_unique ON authentication_hostnames(project_uuid, hostname, session_name)",
	"CREATE INDEX IF NOT EXISTS idx_authentication_hostnames_project_hostname ON authentication_hostnames(project_uuid, hostname)",
	"CREATE INDEX IF NOT EXISTS idx_authentication_hostnames_project_scan ON authentication_hostnames(project_uuid, scan_uuid)",

	// -- scan_logs --
	"CREATE INDEX IF NOT EXISTS idx_scan_logs_project_scan ON scan_logs(project_uuid, scan_uuid)",
	"CREATE INDEX IF NOT EXISTS idx_scan_logs_created_at ON scan_logs(created_at)",

	// -- projects --
	"CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_uuid)",

	// -- agent_sections (durable autopilot) --
	"CREATE INDEX IF NOT EXISTS idx_agent_sections_agentic_scan ON agent_sections(agentic_scan_uuid, seq)",
	"CREATE INDEX IF NOT EXISTS idx_agent_sections_project ON agent_sections(project_uuid)",

	// -- agent_finding_candidates (durable autopilot) --
	"CREATE INDEX IF NOT EXISTS idx_agent_candidates_agentic_scan ON agent_finding_candidates(agentic_scan_uuid, status)",
	"CREATE INDEX IF NOT EXISTS idx_agent_candidates_project ON agent_finding_candidates(project_uuid)",
	// Backs ON CONFLICT (agentic_scan_uuid, dedup_hash) DO NOTHING in SaveCandidate.
	"CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_candidates_dedup ON agent_finding_candidates(agentic_scan_uuid, dedup_hash)",
}

// recordSecondaryIndexes are the non-unique read indexes on http_records.
//
// They are kept apart from the rest of CreateSchema's index list because they
// are the only ones a BULK LOAD can safely postpone: nothing depends on them for
// correctness (uuid is the PRIMARY KEY, and that is what the merge's
// INSERT OR IGNORE dedups on), and they are the most expensive to maintain
// incrementally — thirteen b-tree insertions per row, most of them keyed on a
// random uuid, so every insert dirties thirteen pages in thirteen different
// places. Building them once after the rows are in lets SQLite sort instead.
//
// See DeferRecordIndexes for who postpones them, and CreateRecordIndexes for
// when they are built.
var recordSecondaryIndexes = []string{
	// -- http_records: project-aware composite indexes --
	"CREATE INDEX IF NOT EXISTS idx_records_project_hostname ON http_records(project_uuid, hostname)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_created_uuid ON http_records(project_uuid, created_at, uuid)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_sent_at ON http_records(project_uuid, sent_at)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_host_method_status ON http_records(project_uuid, hostname, method, status_code)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_scheme_host_port ON http_records(project_uuid, scheme, hostname, port)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_risk_score ON http_records(project_uuid, risk_score)",
	"CREATE INDEX IF NOT EXISTS idx_records_project_surface_score ON http_records(project_uuid, surface_score)",
	// Covering index for findDuplicateRecord: the duplicate probe filters on
	// (project_uuid, method, hostname, path, url[, request_hash]) and selects
	// only uuid. Indexing all of those plus uuid lets the lookup resolve
	// entirely from the index (no per-candidate table row fetch). The old
	// 4-column version (…, path) is dropped in CreateSchema so this definition
	// takes effect on existing databases.
	"CREATE INDEX IF NOT EXISTS idx_records_dedup ON http_records(project_uuid, method, hostname, path, url, request_hash, uuid)",
	"CREATE INDEX IF NOT EXISTS idx_records_request_hash ON http_records(request_hash)",
	"CREATE INDEX IF NOT EXISTS idx_records_response_hash ON http_records(response_hash)",
	// Supports DeduplicateDeparosByNormHash: narrows the full http_records scan to
	// the (project, deparos) subset and surfaces response_norm_hash for the
	// reflected-URL-robust dedup pass run after discovery.
	"CREATE INDEX IF NOT EXISTS idx_records_norm_hash ON http_records(project_uuid, source, response_norm_hash)",
	// -- http_records: scan_uuid index --
	"CREATE INDEX IF NOT EXISTS idx_records_project_scan ON http_records(project_uuid, scan_uuid)",
	// -- http_records: source-filtered cursor scan (scan-on-receive) --
	// Supports WHERE source IN (...) AND created_at > cursor filters in
	// DBInputSource.fetchNextBatch and Repository.CountRecordsAfterCursorBySource.
	"CREATE INDEX IF NOT EXISTS idx_records_project_source_created ON http_records(project_uuid, source, created_at, uuid)",
}
