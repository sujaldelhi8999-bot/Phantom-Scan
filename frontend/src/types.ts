export type ScanMode = 'defend' | 'pentest';
export type ScanIntensity = 'low' | 'medium' | 'high';
export type ScanStatus = 'queued' | 'running' | 'cancelling' | 'cancelled' | 'complete' | 'error';
export type AgentState = 'idle' | 'active' | 'complete' | 'error';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Confidence = 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW' | 'POTENTIAL';
export type VerificationMethod = 'dns' | 'http';
export type VerificationStatus = 'PENDING' | 'VERIFIED' | 'EXPIRED' | 'REVOKED';
export type ConnectionState = 'idle' | 'connecting' | 'open' | 'closed' | 'error';

export type TestModule =
  | 'input_security'
  | 'authentication'
  | 'authorization'
  | 'injection'
  | 'xss'
  | 'auth_session'
  | 'access_control'
  | 'csrf'
  | 'ssrf'
  | 'file_upload'
  | 'api_security'
  | 'graphql'
  | 'jwt'
  | 'websocket'
  | 'websockets'
  | 'rate_limits'
  | 'business_logic'
  | 'path_handling'
  | 'redirect'
  | 'redirect_security'
  | 'cors'
  | 'security_headers'
  | 'tls_https'
  | 'sensitive_exposure';

export type RemediationStatus = 'OPEN' | 'IN_PROGRESS' | 'RESOLVED';
export type FindingVerificationStatus = 'NOT_VERIFIED' | 'FIX_VERIFIED' | 'ISSUE_STILL_PRESENT' | 'VERIFY_FAILED';
export type RiskStatus = 'ACTIVE' | 'FALSE_POSITIVE' | 'ACCEPTED_RISK';

export interface BusinessLogicTest {
  name: string;
  method: 'GET' | 'HEAD' | 'OPTIONS';
  path: string;
  expected_status: number;
  description: string;
}

export interface ScanRequestPayload {
  target_url: string;
  mode: ScanMode;
  intensity: ScanIntensity;
  selected_tests?: TestModule[];
  authorization_id?: number | null;
  authorization_confirmed?: boolean;
  business_logic_tests?: BusinessLogicTest[];
}

export interface Finding {
  id: number;
  scan_id: number;
  title: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  target: string;
  endpoint: string;
  evidence: string;
  impact: string;
  recommendation: string;
  verification: string;
  agent: string;
  timestamp: string;
  cve_id: string | null;
  cvss_score: number | null;
  description: string;
  how_exploited: string;
  fix: string;
  parameter?: string | null;
  module?: string | null;
  recommended_fix?: string | null;
  remediation_status?: RemediationStatus;
  verification_status?: FindingVerificationStatus;
  risk_status?: RiskStatus;
}

export interface AICitation {
  type?: string;
  id?: number | string | null;
  label?: string;
  title?: string;
  endpoint?: string;
  source?: string;
}

export interface AIPriority {
  priority: number;
  finding_id?: number | string | null;
  title?: string;
  score?: number;
  severity?: Severity | string;
  confidence?: Confidence | string;
  recommended_action?: string;
  factors?: string[];
  citation?: AICitation;
}

export interface AIDeveloperFinding {
  finding_id?: number | string | null;
  affected_endpoint?: string;
  evidence?: string;
  observed_behavior?: string;
  severity?: Severity | string;
  confidence?: Confidence | string;
  related_findings?: string[];
  technology?: string;
  remediation?: string;
  verification?: string;
  recommended_priority?: number | null;
}

export interface AISecurityAnalystOutput {
  scan_id?: number;
  generated_at?: string;
  ai_available?: boolean;
  ai_status?: string;
  safety?: Record<string, unknown> & { can_start_active_test?: boolean };
  security_summary?: Record<string, unknown>;
  ai_narrative?: string;
  priorities?: AIPriority[];
  related_security_chains?: Array<Record<string, unknown>>;
  root_causes?: Array<Record<string, unknown>>;
  remediation_plan?: Record<string, Array<Record<string, unknown>>>;
  score_explanation?: Record<string, unknown> & { score?: number };
  positive_controls?: Array<Record<string, unknown>>;
  scan_comparison?: Record<string, unknown>;
  security_timeline?: Array<Record<string, unknown>>;
  executive_report?: Record<string, unknown>;
  developer_report?: AIDeveloperFinding[];
  suggested_prompts?: string[];
  citations?: AICitation[];
  grounding?: Record<string, unknown>;
}

export interface AskPhantomScanResponse {
  scan_id: number;
  question: string;
  answer: string;
  citations: AICitation[];
  grounded: boolean;
  can_start_active_test: boolean;
}

export interface FindingAIExplanation {
  finding_id: number;
  language: 'en' | 'hi';
  title?: string;
  summary?: string;
  why_confirmed?: string[];
  why_potential?: string[];
  evidence_required_for_confirmation?: string;
  citations?: AICitation[];
  ai_text?: string;
  cached?: boolean;
  can_start_active_test: boolean;
}

export interface ActiveGateContext {
  allowed: boolean;
  target_url: string;
  target_origin: string;
  authorization_status: 'TRAINING' | 'ALLOWLIST' | 'VERIFIED' | 'BLOCKED' | 'NOT_REQUIRED' | string;
  reason: string;
  authorization_id: number | null;
  is_lab: boolean;
}

export interface ActiveSurface {
  id?: string;
  type?: string;
  method?: string;
  path?: string;
  url?: string;
  parameters?: string[];
  module_hints?: string[];
  auth_required?: boolean | null;
  scenario?: string;
  state?: 'VULNERABLE' | 'PATCHED' | string;
  vulnerable?: boolean;
  description?: string;
}

export interface ActivePlanModule {
  module: string;
  surfaces: ActiveSurface[];
}

export interface ActivePlan {
  target_url?: string;
  source?: string;
  selected_modules: string[];
  modules: ActivePlanModule[];
  surface_count: number;
}

export interface ActiveScore {
  score: number;
  surface_count?: number;
  vulnerable_surface_count?: number;
  finding_count?: number;
  penalty?: number;
  resolved_count?: number;
}

export interface ActiveLimits {
  max_requests: number;
  requests_per_second: number;
  timeout_seconds: number;
  max_response_size: number;
  max_redirects: number;
  max_concurrency: number;
}

export interface ActiveMapRequest {
  target_url: string;
  selected_modules?: TestModule[];
  authorization_id?: number | null;
  authorization_confirmed?: boolean;
}

export interface ActiveMapResponse {
  gate: ActiveGateContext;
  surfaces: ActiveSurface[];
  plan: ActivePlan;
  score: ActiveScore;
  limits: ActiveLimits;
}

export interface ActiveScoreResponse {
  gate: ActiveGateContext;
  score: ActiveScore;
  module_count: number;
  limits: ActiveLimits;
}

export interface ActiveSecurityOutput {
  status?: string;
  target_url?: string;
  attack_surface?: Record<string, unknown>;
  test_plan?: ActivePlan;
  events?: Array<Record<string, unknown>>;
  evidence?: Array<Record<string, unknown>>;
  findings?: Array<Record<string, unknown>>;
  final_report?: string;
  score?: ActiveScore;
  request_count?: number;
  sandbox_id?: string;
}

export interface BrowserSecurityOutput {
  status?: string;
  target_url?: string;
  browser_engine?: string;
  session?: Record<string, unknown>;
  pages?: Array<Record<string, unknown>>;
  routes?: Array<Record<string, unknown>>;
  dom?: Array<Record<string, unknown>>;
  network_events?: Array<Record<string, unknown>>;
  console_events?: Array<Record<string, unknown>>;
  api_inventory?: Array<Record<string, unknown>>;
  storage?: Record<string, unknown>;
  cookies?: Array<Record<string, unknown>>;
  csp?: Array<Record<string, unknown>>;
  csp_violations?: Array<Record<string, unknown>>;
  javascript?: Array<Record<string, unknown>>;
  source_maps?: Array<Record<string, unknown>>;
  auth_flow?: Record<string, unknown>;
  websockets?: Array<Record<string, unknown>>;
  service_workers?: Array<Record<string, unknown>>;
  cache?: Array<Record<string, unknown>>;
  third_party?: Array<Record<string, unknown>>;
  dataflow?: Record<string, unknown>;
  screenshots?: Array<Record<string, unknown>>;
  safety?: Record<string, unknown>;
  correlation?: Record<string, unknown>;
  findings?: Array<Record<string, unknown>>;
  request_count?: number;
}

export interface ScanResponse {
  scan_id: number;
  target_url: string;
  mode: ScanMode;
  intensity: ScanIntensity;
  selected_tests: TestModule[];
  user_id: string;
  authorization_id: number | null;
  authorization_confirmed: boolean;
  status: ScanStatus;
  progress: number;
  request_count: number;
  sandbox_id: string | null;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  findings: Finding[];
}

export interface ScanHistoryItem {
  id: number;
  target_url: string;
  mode: ScanMode;
  status: ScanStatus;
  progress: number;
  created_at: string;
  completed_at: string | null;
}

export interface ScanArtifactsResponse {
  scan_id: number;
  scanner_output: Record<string, unknown> | null;
  shadow_recon_output: Record<string, unknown> | null;
  hindi_findings: Array<Record<string, unknown>> | null;
  markdown_report: string | null;
  notification_result: Record<string, unknown> | null;
  active_security_output: ActiveSecurityOutput | null;
  browser_security_output: BrowserSecurityOutput | null;
  ai_analyst_output: AISecurityAnalystOutput | null;
  updated_at: string | null;
}

export interface LabStatusResponse {
  name: string;
  default_state: 'VULNERABLE' | 'PATCHED' | string;
  scenario_state: Record<string, 'VULNERABLE' | 'PATCHED' | string>;
  scenarios: Record<string, string[]>;
}

export interface LabManifestResponse {
  name: string;
  default_state?: 'VULNERABLE' | 'PATCHED' | string;
  base_path: string;
  users: Record<string, unknown>;
  scenario_state: Record<string, 'VULNERABLE' | 'PATCHED' | string>;
  scenarios: Record<string, string[]>;
  surfaces: ActiveSurface[];
}

export interface LabScenarioRequest {
  state?: 'VULNERABLE' | 'PATCHED';
  scenario?: string | null;
  states?: Record<string, 'VULNERABLE' | 'PATCHED'>;
}

export interface LabScenarioResponse {
  scenario_state: Record<string, 'VULNERABLE' | 'PATCHED' | string>;
}

export interface FindingVerificationResponse {
  finding_id: number;
  module: string;
  status: FindingVerificationStatus;
  remediation_status: RemediationStatus;
  request_count: number;
}

export interface AuditLog {
  id: number;
  scan_id: number;
  agent_name: string;
  action: string;
  timestamp: string;
  details: string;
  user_id: string | null;
  target: string | null;
  authorization_status: string | null;
  selected_module: string | null;
  start_time: string | null;
  end_time: string | null;
  result: string | null;
  request_count: number | null;
  sandbox_id: string | null;
}

export interface AgentStatus {
  name: string;
  status: AgentState;
}

export interface HealthResponse {
  status: 'ok' | 'degraded';
  service: string;
  database: 'available' | 'unavailable';
  scheduler: 'running' | 'stopped' | 'unavailable';
  agents: 'available' | 'unavailable';
  ai_provider: string;
  ai_model: string;
  ai_status: 'connected' | 'offline';
}

export interface SelfAuditStatusResponse {
  status: ScanStatus | 'never_run';
  scan_id: number | null;
  target_url: string | null;
  progress: number | null;
  finding_count: number | null;
  created_at: string | null;
  completed_at: string | null;
}

export interface AuthorizationChallengeRequest {
  target_url: string;
  verification_method: VerificationMethod;
}

export interface AuthorizationChallengeResponse {
  id: number;
  domain: string;
  target_origin: string;
  verification_method: VerificationMethod;
  token: string;
  dns_record: string;
  http_url: string;
  challenge_expires_at: string;
  status: VerificationStatus;
}

export interface AuthorizationStatusResponse {
  id: number | null;
  domain: string;
  target_origin: string;
  verification_method: VerificationMethod | null;
  verified_at: string | null;
  expires_at: string | null;
  status: VerificationStatus;
  message: string;
}

export interface StopScanResponse {
  scan_id: number;
  status: ScanStatus;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  title: string;
  detail?: string;
  agent?: string;
  tone: 'neutral' | 'purple' | 'green' | 'amber' | 'red' | 'blue';
}

export interface ToastEvent {
  title: string;
  detail?: string;
  tone?: TimelineEvent['tone'];
}

export const TEST_MODULES: Array<{ id: TestModule; label: string; group: string; description: string }> = [
  { id: 'input_security', label: 'Input Security', group: 'Application Security', description: 'Controlled input validation and reflection checks.' },
  { id: 'auth_session', label: 'Authentication', group: 'Application Security', description: 'Login, throttling, session, and token behavior checks.' },
  { id: 'access_control', label: 'Access Control', group: 'Access Control', description: 'Role and object access checks.' },
  { id: 'injection', label: 'Injection', group: 'Application Security', description: 'Controlled interpreter error probes.' },
  { id: 'xss', label: 'XSS Reflection', group: 'Application Security', description: 'Harmless reflection checks.' },
  { id: 'csrf', label: 'CSRF Controls', group: 'Application Security', description: 'Passive form protection checks.' },
  { id: 'file_upload', label: 'File Upload', group: 'Application Security', description: 'Upload surface discovery.' },
  { id: 'path_handling', label: 'Path Handling', group: 'Infrastructure', description: 'Controlled path traversal review.' },
  { id: 'api_security', label: 'REST APIs', group: 'API', description: 'HTTP method and API exposure checks.' },
  { id: 'graphql', label: 'GraphQL', group: 'API', description: 'Introspection exposure checks.' },
  { id: 'jwt', label: 'JWT', group: 'Session Security', description: 'Token exposure and claim checks.' },
  { id: 'websocket', label: 'WebSocket', group: 'API', description: 'Socket reference and auth-expectation discovery.' },
  { id: 'redirect', label: 'Redirect Security', group: 'Application Security', description: 'External redirect control checks.' },
  { id: 'cors', label: 'CORS', group: 'Infrastructure', description: 'Untrusted origin policy checks.' },
  { id: 'security_headers', label: 'Security Headers', group: 'Infrastructure', description: 'Browser security header verification.' },
  { id: 'tls_https', label: 'TLS / HTTPS', group: 'Infrastructure', description: 'HTTPS and transport enforcement checks.' },
  { id: 'sensitive_exposure', label: 'Sensitive Exposure', group: 'Infrastructure', description: 'Debug, metadata, and fake-secret exposure checks.' },
  { id: 'business_logic', label: 'Business Logic', group: 'Access Control', description: 'Approved workflow status checks.' },
];

export const DEFEND_CHECKS = [
  'Headers',
  'TLS posture',
  'CORS',
  'Authentication analysis',
  'Access control analysis',
  'API exposure',
  'Session analysis',
  'Infrastructure exposure',
  'Dependency analysis',
  'CVE intelligence',
  'Threat intelligence',
  'AI and Hindi explainers',
  'Remediation checklist',
  'Notifications'
];

export const AGENT_NAMES = [
  'Orchestrator Agent',
  'Scanner Agent',
  'Shadow Recon Agent',
  'Analyzer Agent',
  'CVE Matcher Agent',
  'Authentication Security Agent',
  'Access Control Agent',
  'API Security Agent',
  'Session Security Agent',
  'Injection Analysis Agent',
  'Infrastructure Agent',
  'WebSocket Security Agent',
  'Dependency Agent',
  'Threat Intelligence Agent',
  'Sandbox Manager Agent',
  'Pentest Agent',
  'AI Explainer Agent',
  'AI Security Analyst Agent',
  'Hindi Explainer Agent',
  'Fixer Agent',
  'Notifier Agent',
  'Self Audit Agent'
] as const;
