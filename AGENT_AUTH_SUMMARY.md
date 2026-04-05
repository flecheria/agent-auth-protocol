# Agent Auth Protocol Summary

The Agent Auth Protocol is an open-source standard designed to give AI agents their own cryptographic identity, allowing them to authenticate, discover services, and act autonomously or on behalf of users in a secure, isolated manner.

This document summarizes the core concepts of the protocol and how they interact.

## 1. Identity Model

Unlike traditional OAuth where an application impersonates a user via an access token, Agent Auth gives each agent its own identity using **Ed25519 keypairs**.

The identity model consists of two main actors:
- **Host:** The persistent identity of the client environment where the agent runs (e.g., an MCP server, a CLI, or a background worker). The host registers itself with a server using a Host JWT and manages agent lifecycles.
- **Agent:** The specific runtime AI actor executing a task. Every agent is registered under a host. It gets its own distinct Ed25519 keypair and is granted specific capabilities.

## 2. Authentication with JWTs

Agents and Hosts do not rely on long-lived bearer tokens. Instead, they authenticate by signing short-lived JWTs (JSON Web Tokens) with their private keys.

- **Host JWTs:** Used for management operations like registering new agents, checking status, revoking agents, or key rotation. The `iss` claim is the JWK thumbprint of the host's public key.
- **Agent JWTs:** Used purely for executing granted capabilities. They are extremely short-lived (usually expiring in 60 seconds). Every request to execute a capability uses a fresh Agent JWT signed by the agent's private key. The `aud` claim ensures the token is locked to a specific execution endpoint.

Because the private keys never leave the client, the protocol avoids the risks of token theft typical in bearer token architectures.

## 3. Capabilities and Authorization

Instead of granting broad OAuth scopes (like "read/write access"), servers grant fine-grained **capabilities**.

- A capability is a specific action (e.g., `check_balance` or `transfer_money`) defined by an input/output schema.
- Agents request capabilities during registration.
- Servers can approve these capabilities with **Constraints**. For example, a `transfer_money` capability might be constrained to a specific maximum amount or currency.
- Grants are independently auditable and revocable per agent.

## 4. Agent Modes

Agents can operate in one of two modes:
1. **Delegated Mode:** The agent acts on behalf of a specific human user. Registration usually requires user approval (via standard device authorization or CIBA flows).
2. **Autonomous Mode:** The agent operates without a user in the loop. This is useful for background workers or bootstrapping infrastructure. If a human later claims the agent, the agent transitions to a "claimed" state and its activity is attributed to the user.

## 5. Directory Discovery Mechanism

One of the major innovations of Agent Auth is the **Discovery** mechanism. Agents don't need hardcoded API keys or prior configuration to talk to new services. They can discover services dynamically.

### Well-Known Endpoint
Every Agent Auth server publishes a configuration at `/.well-known/agent-configuration`. This tells the client everything it needs to know: supported modes, endpoints, available cryptographic algorithms, and approval methods.

### The Directory
For intent-based discovery, clients use a **Directory**. A directory is a searchable index of Agent Auth servers.

- An agent describes what it needs in natural language (the **intent**), for instance, `"banking"` or `"send emails"`.
- The client sends this intent to the directory via a search API (`GET /api/search?intent=banking`).
- The directory returns a list of matching providers along with their well-known discovery document details.

This allows agents to organically discover tools they need to complete a task.

#### Directory Security
Directories are trust anchors. To protect against malicious services being returned in search results, directories and clients apply several checks:
- **Issuer Verification:** The directory ensures the `issuer` URL in the discovery document matches the domain actually hosting the configuration.
- **TLS Validation:** All discovery fetches must be over HTTPS with valid certificates.
- **Client-Side Verification:** Clients verify the `issuer` matches before registering agents, providing a robust defense against prompt-injection attacks that attempt to route an agent to a malicious server.

## Summary

By providing a native cryptographic identity via Web Crypto / Ed25519, short-lived signed JWTs, constrained capability grants, and a standardized directory discovery mechanism, Agent Auth elevates AI agents from mere scripts impersonating humans into distinct, auditable, and secure actors on the web.