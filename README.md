# CampusConnect

A full-stack student portal built for Information Security — Practical Assignment 2 (Part 2: Web Security Project).

CampusConnect demonstrates six real, exploitable web vulnerabilities (Reflected XSS, Stored XSS, DOM-based XSS, CSRF, and SQL Injection at three levels of complexity) in a single codebase, toggled between a **Vulnerable Version** and a **Safe Version** via one environment variable — no code duplication, no separate branches.

---

## Use Case

CampusConnect is a simple student portal where logged-in students can:
- View and update their profile bio
- Search for other students by name
- Look up whether a given username exists on the platform

These three features (**bio update**, **search**, **lookup**) are the deliberate attack surfaces for every vulnerability in this assignment.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Node.js + Express |
| Templating | EJS (server-rendered HTML) |
| Database | SQLite (via `better-sqlite3`) |
| Sessions | `express-session` |
| Frontend | Plain HTML/EJS (no frontend framework) |

No separate database server is required — SQLite is a single file (`db/campus.db`).

---

## Project Structure
CampusConnect/
├── server.js # All routes, both vulnerable and safe logic
├── db/
│ ├── init.js # Creates and seeds the SQLite database
│ └── campus.db # SQLite database file (generated)
├── views/
│ ├── login.ejs # Login page
│ └── dashboard.ejs # Main dashboard (bio, search, lookup)
├── package.json
└── README.md

---

## Setup & Installation

### Prerequisites
- Node.js (v18+ recommended)
- npm

### Install dependencies

```bash
npm install
```

### Seed the database

```bash
node db/init.js
```

This creates `db/campus.db` and seeds three test accounts (see **Test Accounts** below).

---

## Running the App — Vulnerable vs Safe Mode

The entire app runs from **one codebase**. A single environment variable, `MODE`, switches every vulnerable feature to its secure equivalent at runtime.

### Run in Vulnerable Mode (default)

```bash
node server.js
```
or explicitly:
```bash
# Windows PowerShell
$env:MODE="vulnerable"; node server.js

# macOS/Linux
MODE=vulnerable node server.js
```

### Run in Safe Mode

```bash
# Windows PowerShell
$env:MODE="safe"; node server.js

# macOS/Linux
MODE=safe node server.js
```

The terminal will confirm the active mode:
CampusConnect running at http://localhost:3000 [MODE=vulnerable]

The app also displays the current mode directly on the dashboard (`Mode: vulnerable` / `Mode: safe`) for clarity during grading/viva.

---

## Test Accounts

| Username | Password |
|---|---|
| `shadow` | `password123` |
| `alice`  | `alicepass` |
| `admin`  | `supersecretadmin` |

---

## Implemented Vulnerabilities & Fixes

### 1. Cross-Site Scripting (XSS) — All 3 Types

| Type | Location | Vulnerable Mechanism | Safe Mode Fix |
|---|---|---|---|
| **Reflected** | Search Students (`/search`) | Search query `q` inserted into HTML via raw string concatenation, rendered with EJS's unescaped `<%- %>` | Parameterized query + output encoding via `escapeHtml()` and EJS's auto-escaping `<%= %>` |
| **Stored** | Profile Bio (`/bio`) | Bio text saved as-is to the database and rendered unescaped on every dashboard load | Rendered with EJS's auto-escaping `<%= %>` tag when in Safe mode |
| **DOM-based** | URL fragment (`#...`) read client-side | Client-side JS reads `location.hash` and injects it via `innerHTML` with no sanitization | Client-side JS uses `textContent` instead of `innerHTML` when `mode === 'safe'` |

**Example payloads used:**
Reflected: <script>alert(‘Reflected XSS’)</script>
Stored: <script>alert(‘Stored XSS’)</script>
DOM: #<img src=x onerror="alert('DOM XSS')">

### 2. Cross-Site Request Forgery (CSRF)

- **Target action:** Updating a logged-in user's bio (`POST /bio`)
- **Vulnerable mode:** No CSRF token is issued or verified; a forged cross-origin form submission (hosted on a different origin, e.g. `localhost:8000`) successfully changes the victim's bio using only their existing session cookie.
- **Safe mode:** A per-session CSRF token is generated (`crypto.randomBytes`), embedded as a hidden field in the real bio-update form, and verified server-side on every `POST /bio` request. Requests missing or presenting an invalid token are rejected with `403 Forbidden`.
- A legacy GET-based demo endpoint (`/bio-update-csrf`) used to showcase the vulnerable behavior is explicitly disabled (`403`) in Safe mode.

**Proof-of-concept attacker page (`evil.html`):**
```html
<form id="csrfForm" action="http://localhost:3000/bio" method="POST">
  <input type="hidden" name="bio" value="HACKED VIA CSRF">
</form>
<script>document.getElementById('csrfForm').submit();</script>
```

### 3. SQL Injection — Three Levels

| Level | Endpoint | Technique | Vulnerable Query | Safe Query |
|---|---|---|---|---|
| **Easy** | `POST /login` | Authentication bypass via `OR` + comment | `` `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'` `` | `db.prepare('SELECT * FROM users WHERE username = ? AND password = ?').get(username, password)` |
| **Intermediate** | `GET /student-lookup` | Blind boolean-based inference (binary search on `SUBSTR()` + ASCII comparison) | `` `SELECT * FROM users WHERE username = '${username}'` `` | `db.prepare('SELECT * FROM users WHERE username = ?').get(username)` |
| **Advanced** | `GET /search` | UNION-based extraction: column count → table/column enumeration via `sqlite_master` → data extraction | `` `SELECT full_name, bio FROM users WHERE full_name LIKE '%${q}%'` `` | `db.prepare('SELECT full_name, bio FROM users WHERE full_name LIKE ?').all('%' + q + '%')` |

**Example payloads used:**
```sql
-- Easy: Authentication bypass
Username: ' OR '1'='1' -- 

-- Intermediate: Blind boolean-based (sample queries from the extraction process)
admin' AND '1'='1
admin' AND LENGTH(password)=16 --
admin' AND SUBSTR(password,1,1) > 'm' --
admin' AND SUBSTR(password,1,1) = 's' --

-- Advanced: Full UNION-based chain
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--                                        -- confirms column count = 2
' UNION SELECT name, sql FROM sqlite_master--          -- table + column enumeration
' UNION SELECT username, password FROM users--         -- data extraction
```

> **Note on `sqlite_master`:** SQLite does not use `information_schema` (a MySQL/PostgreSQL/SQL Server feature). Its functional equivalent is the built-in `sqlite_master` table, which stores the name and full schema (`CREATE TABLE` statement) of every table in the database. The same enumeration methodology (columns → tables → columns → data) applies identically.

---

## Vulnerable vs Safe — Summary of Code-Level Differences

Every vulnerable route in `server.js` branches on the `MODE` environment variable:

```javascript
if (MODE === 'vulnerable') {
  // raw string concatenation — exploitable
} else {
  // parameterized query — safe
}
```

And in `views/dashboard.ejs`, output encoding is similarly conditional:

```ejs
<% if (mode === 'safe') { %>
  <p><%= bioHtml %></p>   <!-- auto-escaped -->
<% } else { %>
  <p><%- bioHtml %></p>   <!-- raw, unescaped -->
<% } %>
```

This keeps both versions in the same file set (as permitted by the assignment brief), while making the vulnerability/fix boundary explicit and easy to demonstrate at the viva by simply restarting the server with a different `MODE` value.

---

## Disclaimer

This application is intentionally vulnerable in its default/vulnerable mode and is built strictly for educational purposes as part of a university Information Security course assignment. Do not deploy this code, in either mode, to a public or production environment.
