# Unauthenticated and Authenticated Recon Agents for Penetration Testing

For a pentest automation platform, the **Unauthenticated Recon Agent** and **Authenticated Recon Agent** should operate as separate discovery agents. Their job is not merely endpoint enumeration. They should build a structured **attack-surface model** that downstream agents can consume.

## 1. Unauthenticated Recon Agent

**Goal:** Determine everything externally reachable and observable **without valid credentials or session state**.

### 1.1 Target Fingerprinting

Identify:

- Hostname / FQDN
- IP addresses
- CDN / reverse proxy
- Load balancer indicators
- WAF indicators
- Cloud/provider fingerprints
- TLS configuration
- HTTP versions
- Server headers
- Technology/framework fingerprints
- Frontend frameworks
- Backend hints
- API technologies
- Authentication technologies advertised publicly
- Third-party integrations
- WebSocket/SSE exposure
- GraphQL exposure
- MCP/AI endpoints where identifiable

Example output:

```text
Target
├── app.example.com
├── api.example.com
├── auth.example.com
└── static.example.com

Observed technologies
├── Cloudflare
├── React / Next.js
├── nginx
├── GraphQL
└── OAuth/OIDC
```

### 1.2 Host and Service Discovery

When the scope permits active network reconnaissance:

- DNS resolution
- Subdomain discovery
- CNAME inspection
- DNS record enumeration
- Certificate SAN discovery
- Open-port discovery
- Service identification
- Service version collection
- Alternate HTTP/HTTPS ports
- Virtual-host discovery
- HTTP service probing

The agent should distinguish:

```text
Observed
Inferred
Unverified
Out of scope
```

Do not automatically turn a fingerprint into a vulnerability.

### 1.3 Web Application Surface Discovery

Crawl the public application and identify:

- Pages
- Routes
- Forms
- Query parameters
- POST parameters
- JSON inputs
- File-upload functionality
- Redirect parameters
- Search functionality
- Object identifiers
- API calls
- Static resources
- JavaScript bundles
- Source maps
- WebSocket endpoints
- SSE endpoints
- GraphQL endpoints
- Authentication endpoints

Build something like:

```json
{
  "endpoint": "/api/search",
  "method": "GET",
  "authentication": false,
  "inputs": [
    {
      "name": "q",
      "location": "query"
    }
  ],
  "content_type": "application/json"
}
```

This becomes input for later attack agents.

### 1.4 JavaScript / Client-Side Recon

Extract from JavaScript bundles:

- API base URLs
- Hidden endpoints
- Internal route names
- API versions
- GraphQL endpoints
- WebSocket URLs
- SSE URLs
- Feature flags
- Cloud storage URLs
- Authentication configuration
- OAuth/OIDC client IDs
- Redirect URIs
- Scope names
- Tenant IDs where exposed
- Third-party service endpoints
- Debug endpoints
- Environment names
- Source map locations
- Function/operation names
- Parameter names
- Potential secrets/tokens accidentally embedded in frontend artifacts

Correlation flow:

```text
JS-discovered endpoint
        ↓
Is it reachable?
        ↓
Authentication required?
        ↓
Method?
        ↓
Parameters?
        ↓
Interesting security properties?
```

### 1.5 API Recon

Discover REST/API behavior including:

- Base paths
- API versions
- Methods
- Parameters
- Headers
- Content types
- Required/optional fields
- Error formats
- Object IDs
- Pagination
- Filtering
- Sorting
- Bulk endpoints
- Import/export functions
- Upload/download APIs
- Callback/webhook parameters

Passive specification discovery:

- `swagger.json`
- `openapi.json`
- Swagger UI
- API documentation
- Postman artifacts
- GraphQL schema exposure
- Application-specific API metadata

The output should become a machine-readable **API inventory**.

### 1.6 Authentication Surface Recon

Even though the agent does not authenticate, it should map authentication.

Identify:

- Login page
- Registration
- Password reset
- Username/email recovery
- MFA flow
- SSO
- OAuth
- OIDC
- SAML
- Magic links
- Device authentication
- API-key authentication
- Bearer-token authentication
- Session-cookie authentication

For OAuth/OIDC:

```text
authorization endpoint
token endpoint
client_id
redirect_uri
response_type
scopes
PKCE usage observable from client
logout endpoint
callback routes
```

Do not label missing or weak controls unless actually tested.

### 1.7 Public Information Exposure Recon

Inspect responses/resources for:

- Stack traces
- Debug output
- Framework errors
- Internal hostnames
- Filesystem paths
- Internal IP addresses
- Software versions
- Environment identifiers
- API metadata
- Source maps
- Configuration files
- Backup artifacts
- Public directory listings
- Exposed API documentation

### 1.8 Security-Control Recon

Record observed controls:

- CSP
- HSTS
- CORS behavior
- Cookie attributes
- CSRF mechanisms
- Rate-limiting observations
- WAF behavior
- Cache headers
- Authentication challenges
- Request-size constraints
- Content-type validation
- Redirect behavior

This is **observation**, not a security verdict.

### 1.9 Unauthenticated Workflow Mapping

The agent should understand what an anonymous user can actually do.

Example:

```text
Landing page
   ↓
Product Search
   ↓
Product Details
   ↓
Add to Cart
   ↓
Login Required
```

This gives downstream agents **state-transition information**, not just URLs.

---

## 2. Authenticated Recon Agent

**Goal:** Map everything exposed after authentication and understand application objects, permissions, roles, workflows, and backend/API relationships.

This agent starts with credentials or session material supplied for the authorized assessment.

### 2.1 Session Bootstrap

Support:

- Username/password
- Cookies
- Bearer tokens
- API keys
- OAuth access tokens
- JWTs
- Captured Burp requests
- Existing authenticated sessions
- Custom authentication headers

Track:

```text
Authentication mechanism
Session/token location
Token expiration where observable
Refresh behavior where observable
Session renewal
Logout behavior
CSRF token requirements
```

Credentials and tokens should be treated separately from ordinary reconnaissance artifacts and redacted from normal logs and reports.

### 2.2 Authenticated Crawl

After login, enumerate:

- Dashboard
- Profile
- Settings
- Account management
- Administrative interfaces
- Search
- CRUD workflows
- Uploads/downloads
- Reports
- Exports
- Imports
- Notifications
- Integrations
- Organization/team functionality
- Billing where in scope
- Developer/API settings
- AI functionality
- Internal APIs

Build a state-aware site map.

### 2.3 Authenticated API Discovery

This is especially important because SPAs frequently expose more surface after authentication.

Capture:

```text
GET /api/users/me
GET /api/projects
POST /api/projects
GET /api/projects/{id}
PATCH /api/projects/{id}
DELETE /api/projects/{id}
POST /api/files/upload
GET /api/files/{id}
```

For every endpoint record:

```json
{
  "endpoint": "/api/projects/{id}",
  "methods": ["GET", "PATCH", "DELETE"],
  "authentication": true,
  "object_type": "project",
  "identifiers": ["id"],
  "observed_roles": ["user"],
  "parameters": [],
  "response_fields": []
}
```

### 2.4 Object Discovery

Authenticated recon should understand **business objects**, not merely endpoints.

Examples:

```text
User
Organization
Tenant
Project
Workspace
Document
File
Order
Invoice
Ticket
Conversation
Agent
Workflow
API Credential
Integration
```

Correlate identifiers:

```text
project_id
user_id
tenant_id
account_id
document_id
conversation_id
workspace_id
```

This creates the foundation for authorization testing.

### 2.5 Authorization Boundary Mapping

With multiple authorized test accounts or roles, build a matrix such as:

```text
                 User-A    User-B    Manager    Admin
View own object     ✓         ✓         ✓         ✓
Edit own object     ✓         ✓         ✓         ✓
View other's       test      test      test       test
Delete object      test      test      test       test
Admin API          test      test      test       test
```

Important distinction:

> Recon discovers and maps the boundary. A separate authorization-testing capability should determine whether the boundary can actually be violated.

### 2.6 Role Discovery

Determine roles from observed application behavior and responses:

- Standard user
- Read-only user
- Moderator
- Manager
- Organization administrator
- Application administrator
- Service account
- API user

Look for role information in:

- JWT claims
- `/me` endpoints
- User/profile APIs
- UI controls
- API responses
- Route availability

Do not infer privilege solely because the UI shows or hides an element.

### 2.7 Tenant / Organization Mapping

For multi-tenant applications identify:

```text
Tenant
 ├── Users
 ├── Groups
 ├── Projects
 ├── Documents
 └── Integrations
```

Capture tenant-scoped identifiers and relationships.

This is especially valuable for later BOLA/IDOR and tenant-isolation testing.

### 2.8 Workflow Discovery

Authenticated recon should model sequences.

Example:

```text
Create Project
      ↓
Upload Document
      ↓
Process Document
      ↓
Generate Report
      ↓
Share Report
      ↓
Download
```

Capture which API request corresponds to every transition.

This enables later workflow and business-logic testing such as:

- Step skipping
- Sequence manipulation
- Repeated actions
- Parameter substitution
- State manipulation
- Cross-object interaction

### 2.9 Hidden Functionality Discovery

Compare:

```text
UI functionality
        vs
JS-discovered functionality
        vs
API-observed functionality
```

This can expose functionality reachable through APIs but not currently presented in the UI.

Examples:

```text
/admin/*
/internal/*
/api/v1/debug/*
/api/v2/*
/export/*
/bulk/*
```

Presence alone should be recorded as an attack-surface observation until access and behavior are tested.

### 2.10 File Handling Recon

Identify:

- Upload endpoints
- Download endpoints
- Preview functionality
- Import/export
- Image processors
- Document converters
- Archive processing
- Remote-URL import
- Object-storage links
- Signed URLs

Record:

```text
accepted extension
observed MIME behavior
size constraints
storage location hints
download authorization model
identifier format
```

These can feed dedicated file-upload, parser, SSRF, and authorization testing agents.

### 2.11 GraphQL Recon

If GraphQL exists:

- Endpoint detection
- Introspection availability
- Operation names
- Queries
- Mutations
- Subscriptions
- Types
- Arguments
- Input objects
- Object identifiers
- Authorization-relevant fields

Create a relationship graph:

```text
User
 ├── organizations
 │    └── projects
 │         └── documents
 └── profile
```

This is more useful than dumping the schema alone.

### 2.12 WebSocket / SSE Recon

For realtime or agentic applications detect:

- WebSocket URL
- SSE endpoint
- Authentication mechanism
- Connection parameters
- Event/message types
- Subscription identifiers
- Conversation IDs
- Agent/run IDs
- Reconnection behavior
- Message schemas

### 2.13 AI / LLM Application Recon

Identify the observable architecture:

```text
User
 ↓
Frontend
 ↓
Chat/Agent API
 ↓
Orchestrator
 ↓
LLM
 ↓
Tools / MCP
 ↓
Backend resources
```

Discover where observable:

- Chat endpoint
- Conversation endpoint
- Streaming endpoint
- Model/provider metadata
- Agent endpoints
- File/RAG endpoints
- Tool-call messages
- MCP connections
- Tool names
- Tool arguments
- Agent/run identifiers
- Citation/document retrieval
- Upload/attachment functionality
- Conversation history
- Memory APIs
- Workflow endpoints

The recon agent should identify **where input can enter the system and where output or data leaves it**.

### 2.14 MCP Recon

If an application exposes or uses MCP and sufficient information is available to the tester, map:

```text
MCP server
├── tools
├── resources
├── prompts
└── capabilities
```

For discovered tools capture:

```json
{
  "tool": "search_files",
  "arguments": {
    "query": "string"
  },
  "observed_auth_context": "authenticated",
  "source": "mcp"
}
```

Also map:

```text
LLM → MCP
MCP → internal API
MCP → filesystem
MCP → database
MCP → SaaS/cloud service
```

Only relationships established by observed evidence should be marked confirmed.

---

## 3. Shared Capabilities for Both Recon Agents

### 3.1 Parameter Classification Engine

Both recon agents should classify every discovered input.

Example:

```text
/api/files?id=123
              ↑
       object identifier

/api/fetch?url=https://...
               ↑
          URL parameter

/api/search?q=test
              ↑
        free-form input

/api/export?path=...
               ↑
          path-like input
```

Useful classes:

```text
OBJECT_ID
USER_ID
TENANT_ID
URL
FILE
PATH
COMMAND_LIKE
SEARCH
FREE_TEXT
HTML
JSON
XML
GRAPHQL
REDIRECT
CALLBACK
TOKEN
HEADER
COOKIE
UPLOAD
AI_PROMPT
MCP_ARGUMENT
```

This allows the attack planner to route endpoints to appropriate testing modules.

### 3.2 Differential Recon

#### Anonymous vs Authenticated

```text
Endpoint             Anonymous    Authenticated
/api/profile            401            200
/api/search             200            200
/api/admin              403            403
```

#### Account A vs Account B

```text
Object       Account A       Account B
Project A       200             test
Project B       test            200
```

#### User vs Admin

Compare:

- Routes
- APIs
- Fields
- Methods
- Object visibility
- Response codes
- UI capabilities

Different responses indicate a boundary worth testing, not automatically a vulnerability.

### 3.3 Intelligent Endpoint Prioritization

The recon layer can give downstream testing an **interest score**, not a vulnerability score.

Example:

```text
POST /api/import
Interest: HIGH

Reasons:
- authenticated
- accepts file
- creates server-side object
- complex processing workflow
```

Other high-interest patterns:

```text
/admin
/export
/import
/upload
/download
/proxy
/fetch
/render
/template
/search
/graphql
/webhook
/callback
/redirect
/internal
/debug
/execute
/chat
/agent
/tools
/mcp
```

The score means **test this first**, not **this is vulnerable**.

### 3.4 Evidence Collection

Every discovery should retain provenance.

```json
{
  "endpoint": "/api/projects/123",
  "discovered_by": "authenticated_crawler",
  "source": "network_response",
  "evidence": {
    "request_id": "req_00291",
    "response_id": "res_00291"
  }
}
```

Save:

- Raw request
- Raw response
- HTTP status
- Timestamp
- Authentication context
- Originating page
- Discovery mechanism
- Redirect chain
- Content type
- Relevant headers

This allows the downstream LLM to distinguish **observed facts from hypotheses**.

---

## 4. What the Recon Agents Should Not Do

Enforce this architectural boundary:

```text
Recon Agent
    ↓
Discover + Map + Classify
    ↓
Attack Planner
    ↓
Testing Agents
    ↓
Verification
    ↓
Finding Correlator
    ↓
Report
```

The recon agent should not report the following merely because it found a parameter or suspicious endpoint:

```text
SQL Injection found
IDOR confirmed
SSRF confirmed
Authentication bypass
RCE
```

Instead:

```text
Potential SQLi injection point identified
→ send to Injection Agent

Object identifier discovered
→ send to Authorization Agent

URL parameter discovered
→ send to SSRF Agent

MCP tool discovered
→ send to MCP Security Agent
```

Actual vulnerabilities require testing and evidence.

---

## 5. Recommended Architecture

```text
                 TARGET
                    │
        ┌───────────┴───────────┐
        │                       │
 UNAUTH RECON AGENT      AUTH RECON AGENT
        │                       │
        └───────────┬───────────┘
                    │
            ATTACK SURFACE DB
                    │
        ┌───────────┼────────────┐
        │           │            │
    Endpoints     Objects     Workflows
        │           │            │
    Parameters    Roles       State Graph
        │           │            │
        └───────────┼────────────┘
                    │
             ATTACK PLANNER
                    │
      ┌─────────────┼──────────────┐
      │             │              │
 Web/API Agent   AI Agent      MCP Agent
      │             │              │
 Injection      Prompt/Agent    Tool Security
 Auth/AuthZ      RAG/etc.       MCP boundaries
      └──────────────┬─────────────┘
                     │
               VERIFICATION
                     │
                  EVIDENCE
                     │
            FINDING CORRELATOR
                     │
                 REPORT
```

## 6. Core Design Principle

Recon should never restrict the vulnerability classes tested. It should determine **where and how to test**, then allow the autonomous planner to prioritize the full applicable attack arsenal based on the discovered surface.
