<!--
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 -->

# OpenFGC Portal

OpenFGC Portal is a user interface for managing consents through the OpenFGC Consent Management API.

## Architecture

The React frontend calls the Go Portal Backend, which authenticates users through an OpenID Connect identity provider, enforces authorization, and forwards allowlisted requests to OpenFGC.

```text
React frontend ──► Portal Backend ──► OpenFGC
                       │
                       └────────► OIDC identity provider
```

The browser never stores the OIDC client secret or calls OpenFGC directly.

## Quickstart

1. [Start the OpenFGC consent server](../README.md#quick-start).
2. [Configure and start the Portal Backend](backend/README.md#quickstart).
3. [Configure and start the Portal Frontend](frontend/README.md#quickstart).
4. Open `http://localhost:5173`.

## Components

- [Portal Frontend development and configuration](frontend/README.md)
- [Portal Backend development and configuration](backend/README.md)

For authentication flows, authorization, routing, security, and deployment details, see the [portal architecture and operations guide](backend/docs/README.md).
