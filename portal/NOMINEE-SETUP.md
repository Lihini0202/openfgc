# Nominee feature - setup 

Follow in order. Each step depends on the one before it.

---

## What you need first

| | Version | Used by |
|---|---|---|
| WSO2 Identity Server | 7.3.0 | login, impersonation |
| Java (JDK) | 21 | nominee-service, IS extension |
| Maven | 3.9+ | building both |
| Go | 1.25+ | portal backend, consent server |
| Node | 20+ | portal frontend |
| pnpm | 9+ | portal frontend |
| MySQL / PostgreSQL / SQLite | - | nominee-service, consent server |

### Installing them

**Windows** (PowerShell as administrator):

```powershell
winget install EclipseAdoptium.Temurin.21.JDK
winget install Apache.Maven
winget install GoLang.Go
winget install OpenJS.NodeJS.LTS
winget install Oracle.MySQL          # or PostgreSQL / SQLite
npm install -g pnpm
```

**macOS:**

```bash
brew install temurin@21 maven go node mysql
npm install -g pnpm
```

**Linux (Debian/Ubuntu):**

```bash
sudo apt update
sudo apt install -y openjdk-21-jdk maven golang-go nodejs npm mysql-server
sudo npm install -g pnpm
```

WSO2 Identity Server is a separate download:
[wso2.com/identity-server](https://wso2.com/identity-server/) — take 7.3.0 and
unzip it. `$IS_HOME` below means that directory.

Check everything resolves before continuing:

```bash
java -version     # 21
mvn -version      # 3.9+
go version        # 1.25+
node --version    # 20+
pnpm --version    # 9+
mysql --version
```

A wrong `java -version` is the most common cause of a confusing build failure -
if you have several JDKs, set `JAVA_HOME` to the 21 one.

---

## 1. Identity Server

This is the part with no shortcuts. Nothing else works until it is right.

### 1.1 Create the application

Console → **Applications → New Application → Standard-Based Application → OpenID Connect**.

Name it whatever you like. Then under **Protocol**:

| Setting | Value |
|---|---|
| Grant types | `authorization_code`, `refresh_token`, `client_credentials`, **`urn:ietf:params:oauth:grant-type:token-exchange`** |
| Authorized redirect URLs | `http://localhost:8080/auth/callback`, `http://localhost:5173/`, `http://localhost:5173/acting/callback` |
| Access token type | JWT |
| **Subject token** | **enabled**, expiry `300` seconds |

Then under **Advanced**, tick **Skip login consent**. This is a first-party
portal, so users should not be asked to authorise their own organisation's
application. Leaving it off means every user meets a consent screen the first
time, and again whenever the requested scopes change - which breaks the login
redirect and is hard to recognise when it happens.

The token-exchange grant and the subject token are what make delegation
possible. Without both, the flow stops at step 5 of the Postman collection.

Copy the **Client ID** and **Client Secret** - three services need them.

### 1.2 Set the subject claim

Console → your application → **User Attributes** → **Subject** →
`http://wso2.org/claims/userid`.

This one is easy to miss and hard to diagnose. The default subject is the
*username*, but nominations are keyed on the user's **id**. With the wrong
subject the gate looks up a nomination for `test2` instead of
`496152f4-...`, finds nothing, and refuses every request while appearing
correctly configured.

### 1.3 Register the API scopes

Console → **API Resources → New API Resource**. Identifier can be anything;
add these eight scopes:

```
portal:consents:read:self
portal:consents:write:self
portal:consents:approve:self
portal:profile:read:self
portal:profile:write:self
portal:profile:delete:self
portal:profile:read:any
portal:profile:write:any
```

`:self` means "the subject of this token" - which, in an impersonation token, is
the owner. That is what lets one scope set cover both a user acting for
themselves and a nominee acting for someone else. `:any` is administrative and
is never delegated.

Authorize this API resource on the application, and also authorize the built-in
**`internal_user_impersonate`** scope.

### 1.4 Create the roles

Console → **Roles → New Role**, audience **Application**, on your application:

| Role | Scopes | Given to |
|---|---|---|
| `PortalUser` | the six `:self` scopes + `internal_user_impersonate` | every user |
| `PortalAdmin` | `portal:profile:read:any`, `portal:profile:write:any` | administrators only |

Owners and nominees are both just users - the same person is an owner of their
own data and a nominee of somebody else's. Only the administrator who activates
nominations needs `PortalAdmin`.

### 1.5 Build and deploy the impersonation validator

```bash
cd is-extensions/nomination-extension-accelerator
mvn clean package
cp target/nomination-extension-accelerator-1.5.0.jar \
   $IS_HOME/repository/components/dropins/
```

**Remove any older version of the jar first.** Two copies mean two validators
registered.

Also remove stale entries from
`$IS_HOME/repository/components/default/configuration/org.eclipse.equinox.simpleconfigurator/bundles.info`
- deleting the jar is not enough. An entry pointing at a jar that no longer
exists stops the bundle loading, silently and with no error.

If the validator does not load, the usual cause is a new `Import-Package` entry
getting a strict version range from the bundle plugin's wildcard. WSO2 exports
these packages unversioned, so each must be listed explicitly with
`version="[0,9)"` in `pom.xml`.

### 1.6 Start IS

```bash
cd $IS_HOME/bin
./wso2server.sh          # wso2server.bat run on Windows
```

No JVM flags, no wrapper script. If you find yourself needing either, something
is wrong - see *Troubleshooting*.

---

## 2. Nominee Service

```bash
cd nominee-service
mvn clean package
```

Create the schema - pick one database:

```bash
# MySQL
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS nominee_mgt;"
mysql -u root -p nominee_mgt < dbscripts/db_schema_mysql.sql

# PostgreSQL
psql -U postgres -c "CREATE DATABASE nominee_mgt;"
psql -U postgres -d nominee_mgt -f dbscripts/db_schema_postgres.sql

# SQLite
mkdir -p data && sqlite3 data/nominee-service.db < dbscripts/db_schema_sqlite.sql
```

Set the Identity Server values in `src/main/resources/application.yml` to match
your application — `issuer-uri`, `jwk-set-uri`, and `audience` (the client id).

Then run:

```bash
export NOMINEE_DB_TYPE=mysql
export NOMINEE_DB_USER=root
export NOMINEE_DB_PASSWORD=<password>
export IMPERSONATION_GATE_KEY=<pick a shared secret>
java -jar target/nominee-service-0.1.0.jar
```

Full options in `nominee-service/README.md`.

---

## 3. Consent Server

```bash
./build.sh build
```

Create its schema from `consent-server/dbscripts/` and configure
`target/server/repository/conf/deployment.yaml`. See the root `README.md`.

```bash
cd target/server && ./consent-server
```

---

## 4. Portal Backend

```bash
cd portal/backend
cp .env.example .env
```

Fill in `.env`:

| Variable | Value |
|---|---|
| `BFF_IDENTITYSERVER__BASE_URL` | `https://localhost:9443` |
| `BFF_IDENTITYSERVER__CLIENT_ID` | from step 1.1 |
| `BFF_IDENTITYSERVER__CLIENT_SECRET` | from step 1.1 |
| `BFF_IDENTITYSERVER__REDIRECT_URI` | `http://localhost:5173/acting/callback` |
| `BFF_INTERNAL__NOMINEE_SERVICE_URL` | `http://localhost:8082` |
| `BFF_INTERNAL__GATE_API_KEY` | the same secret as `IMPERSONATION_GATE_KEY` |

The gate key must match on both sides. The backend refuses to start if any of
these are missing rather than falling back to a default secret.

```bash
task run:env
```

---

## 5. Portal Frontend

```bash
cd portal/frontend
cp .env.example .env
pnpm install
pnpm dev
```

---

## 6. Create test users

In the IS console, create at least three users and assign both the `PortalUser`
role. Assign `PortalAdmin` to one of them.

They must have an **email address** - nominations are created by looking a
person up by email.

---

## Verify it works

Import `portal/OpenFGC-Nominee-IS-Tokens.postman_collection.json`, set
`client_secret`, `nominee_password` and `outsider_password`, then
**Run Collection**. Thirteen requests in two folders, no browser needed.

**Folder A - a nominee acts for an owner.** Three tokens, each saying something
different:

| Step | Token | Says |
|---|---|---|
| 4 | login | `sub` = nominee, no delegation claim |
| 5 | subject | `sub` = owner, `may_act` = nominee |
| 6 | impersonation | `sub` = owner, `act` = nominee |

If step 5 returns no token, the nomination is not `ACTIVE` or the validator did
not load. If step 6 returns 400, check that all four token parameters are being
sent.

**Folder B - a non-nominee is refused.** The same API calls, made by a valid
signed-in user who was never nominated for the account they reach for. Every
request is expected to be refused, so a green run means the refusals happened:

| Step | Result | Shows |
|---|---|---|
| 10 | token issued | the caller is a real user holding *every* portal scope, including `internal_user_impersonate` |
| 11 | **no token, error returned** | the nomination check refuses it - scope was never what stopped them |
| 12 | `{"active":false,"permissions":[]}` | the gate, asked directly, is the reason |
| 13 | `401` | with no impersonation token there is nothing to act with |

Step 11 is the one to look at. Confirm it in the IS log:

```
WARN ... Impersonation denied: no active nomination. owner=... nominee=...
```

Step 7 keeps folder B honest. Postman uses one cookie jar for the whole run, so
the Identity Server session created at step 2 is still live and still being sent.
Left alone, IS recognises it, skips the login page, and folder B signs in as the
*nominee* again - every assertion then passes for the wrong reason.

Two measures prevent that, and either works on its own:

1. the pre-request script clears the cookie jar - `pm.cookies.jar().clear(...)`
2. `prompt=login` asks IS to authenticate again regardless of any session

Both are kept, so removing one does not silently turn folder B into a second run
of folder A. To confirm the isolation held, check the console for
`cookie jar cleared for ...`, and that step 10 reports the **non-nominee's**
`sub`, not the nominee's.

Set `outsider_username`/`outsider_id` to a user who is **not** a nominee of
`not_nominated_owner_id`. The defaults pair two of the test users in the
opposite direction to the nomination, which is why no nomination exists.

Then in the browser: sign in as the owner, add a nominee, sign in as the nominee
and accept, sign in as the admin and activate, then act.

---

## Troubleshooting

**The login page returns 404.** An extension is initialising the JVM's default
SSL context before the server configures TLS, which breaks every later HTTPS
client including IS's own. Do not work around it with truststore flags - find
what is building an HTTP client at startup and make it lazy.

**Every request is refused with "no active nomination".** Usually the subject
claim (step 1.2). Check what `sub` actually contains in the token: it must be a
UUID, not a username.

**The exchange fails with "subject token is not ACTIVE".** Misleading message.
It means the request was not recognised as impersonation at all - all four of
`subject_token`, `subject_token_type`, `actor_token` and `actor_token_type` must
be present.

**The validator never logs.** The bundle did not resolve. See step 1.5.

---

## What is not built yet

So expectations are set before you start:

- Only `CONSENT_VIEW`, `CONSENT_REVOKE` and `CONSENT_APPROVE` are enforced. `ACCOUNT_VIEW`,
  `ACCOUNT_UPDATE` and `ACCOUNT_DELETE` can be granted and are
  carried in the token, but no endpoint acts on them.
- Notifications are not wired to a mail server, so events are dropped.
- An owner can widen a grant after an administrator has activated it.
