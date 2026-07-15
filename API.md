SkyGlobe Group — API Reference
All endpoints are served by `server.js`. Base URL is the site origin
(`http://localhost:3000` in development).
Authentication
Audience	Mechanism	How it's sent
Clients (public site accounts)	HMAC session token from `/api/auth/login`	`Authorization: Bearer <token>`
Parents (Kids Academy)	HMAC session token from `/api/academy/parent/login`	`Authorization: Bearer <token>`
Admin / CEO	Admin key	`x-admin-key: <key>` header
Staff	Staff session	issued by `/api/staff/login`
SSE	token via query string (EventSource can't set headers)	`/api/sse?token=<token>`
Tokens are HMAC-SHA256 signed and expire after 30 days
(see `lib/utils.js` → `signToken` / `verifyToken`).
---
Health & diagnostics
Method	Path	Auth	Description
GET	`/api/health`	—	Liveness check (also used by keep-alive ping)
GET	`/api/test`	—	Basic server test
GET	`/api/test-ai`	—	Test the AI fallback chain
GET	`/api/test-gemini`	—	Test the Gemini provider
Realtime
Method	Path	Auth	Description
GET	`/api/sse?token=…`	client or admin (query)	Server-Sent Events stream for live updates
Public site — applications & contact
Method	Path	Auth	Description
POST	`/api/contact`	—	Contact form submission
POST	`/api/apply`	—	Submit a service application
GET	`/api/apply/:ref`	—	Look up an application by reference
GET	`/api/apply`	admin	List applications (admin)
POST	`/api/work-permit/apply`	—	Work-permit application
GET	`/api/work-permit/requirements`	—	Work-permit requirements
POST	`/api/conference/request`	—	Request a conference invitation
GET	`/api/conferences`	—	List conferences
Client accounts
Method	Path	Auth	Description
POST	`/api/auth/signup`	—	Create a client account
POST	`/api/auth/login`	—	Log in, returns session token
GET	`/api/auth/me`	client	Current account
GET	`/api/client/documents`	client	Documents for the logged-in client
GET	`/api/messages`	client	Client message inbox
POST	`/api/messages`	client	Send a message
AI engine
Method	Path	Auth	Description
POST	`/api/chat`	—	General AI chat
POST	`/api/ai-tips`	—	AI tips
POST	`/api/country-info`	—	Country information
POST	`/api/country-compare`	—	Compare countries
POST	`/api/interview-prep`	—	Interview preparation (may be paywalled)
POST	`/api/generate-doc`	—	Generate a document draft
POST	`/api/letterhead-draft`	—	Letterhead studio draft
POST	`/api/ceo/assistant`	admin	CEO AI assistant
Legal documents
Method	Path	Auth	Description
GET	`/api/legal-docs/catalog`	—	Catalogue of legal documents
POST	`/api/legal-docs/generate`	—	Generate a legal document
GET	`/api/admin/legal-docs`	admin	List generated legal docs
POST	`/api/admin/legal-docs/:id/resend`	admin	Resend a legal document
Secure document viewer
Method	Path	Auth	Description
POST	`/api/documents`	client	Create a secure document
GET	`/api/documents/:ref`	—	Document metadata by reference
DELETE	`/api/documents/:id`	admin	Delete a document
GET	`/api/view/:token`	token	Open a tokenised document
GET	`/api/view/:token/content`	token	Document content
POST	`/api/admin/documents/:id/new-token`	admin	Re-issue a view token
Payments
Method	Path	Auth	Description
GET	`/api/pay/config`	—	Public payment config
POST	`/api/pay/init`	—	Initialise a payment
GET	`/api/pay/verify/:reference`	—	Verify a payment
POST	`/api/pay/webhook/paystack`	provider	Paystack webhook
GET	`/api/admin/payments`	admin	List payments
See `PAYMENTS_SETUP.md` for provider configuration.
Kids Academy — admissions & parents
Method	Path	Auth	Description
POST	`/api/academy/admission/apply`	—	Submit an admission application
GET	`/api/academy/admission/:id/status`	—	Admission status
PATCH	`/api/academy/admission/:id/review`	admin	Mark under review
PATCH	`/api/academy/admission/:id/accept`	admin	Accept
PATCH	`/api/academy/admission/:id/enroll`	admin	Enroll
POST	`/api/academy/parent/signup`	—	Parent signup
POST	`/api/academy/parent/login`	—	Parent login
GET	`/api/academy/materials`	parent	Learning materials
GET	`/api/academy/progress/:studentId`	parent	Student progress
Kids Academy — teaching & records
Method	Path	Auth	Description
POST	`/api/academy/tutor`	—	AI tutor session
GET	`/api/academy/teacher/:subject`	—	Teacher for a subject
GET	`/api/academy/roster`	admin	Class roster
GET	`/api/academy/students`	admin	List students
POST	`/api/academy/student`	admin	Create a student
GET	`/api/academy/student/:id/academic-record`	admin	Academic record
GET	`/api/academy/student/:id/attendance`	admin	Attendance
GET	`/api/academy/student/:id/assessments`	admin	Assessments
POST	`/api/academy/student/:id/assessments`	admin	Add an assessment
GET	`/api/admin/academy/admissions`	admin	All admissions
GET	`/api/admin/academy/teachers`	admin	AI teacher names
PATCH	`/api/admin/academy/teachers/:key`	admin	Update a teacher name
Staff portal
Method	Path	Auth	Description
POST	`/api/staff/login`	—	Staff login
GET	`/api/staff/profile`	staff	Staff profile
POST	`/api/staff/clock`	staff	Clock in/out
GET	`/api/staff/attendance`	staff	Own attendance
GET	`/api/staff/tasks`	staff	Assigned tasks
PATCH	`/api/staff/tasks/:id`	staff	Update a task
GET	`/api/team/messages` / POST	staff	Team channel
GET	`/api/dept/messages` / POST	staff	Department channel
Admin / CEO portal
Method	Path	Auth	Description
POST	`/api/admin/login`	—	Admin login
POST	`/api/admin/update`	admin	Update settings
GET	`/api/admin/applications`	admin	Applications
GET	`/api/admin/messages` / POST	admin	Messages
POST	`/api/admin/note`	admin	Add a note
GET	`/api/admin/staff` / POST	admin	Staff accounts
PATCH/DELETE	`/api/admin/staff/:id`	admin	Edit / remove staff
GET	`/api/admin/payroll` / POST	admin	Payroll
PATCH/DELETE	`/api/admin/payroll/:id`	admin	Edit / remove payroll
GET	`/api/admin/tasks` / POST	admin	Task board
PATCH/DELETE	`/api/admin/tasks/:id`	admin	Edit / remove task
GET	`/api/admin/attendance`	admin	Staff attendance
GET	`/api/admin/activity`	admin	Activity log
GET	`/api/admin/conferences` (+POST/DELETE)	admin	Manage conferences
GET	`/api/admin/brand-assets` (+POST/PATCH/DELETE)	admin	IP / brand registry
Analytics & error monitoring (self-hosted)
Method	Path	Auth	Description
POST	`/api/analytics/event`	— (rate-limited)	Record a first-party event
GET	`/api/admin/analytics`	admin	Analytics data
POST	`/api/log-error`	— (rate-limited)	Client-side error report
GET	`/api/admin/errors`	admin	Recent error log
---
Conventions
Rate limiting — public write endpoints (analytics, errors, auth) are
throttled by a pure in-memory limiter.
Errors — unhandled exceptions are caught by a global Express error handler
that logs to the error table and returns `{ "error": "Internal server error" }`
with HTTP 500.
Sanitization — all user input passes through `sanitize` / `sanitizeEmail`
(`lib/utils.js`) before storage.
No cookies — sessions are bearer tokens; analytics are cookieless.
© SkyGlobe Group. One World. One Mission.
