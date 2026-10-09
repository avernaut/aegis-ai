# AegisAI Language Draft v0.4

AegisAI v0.4 is an experimental language for **bounded autonomous intelligence**. It separates AI reasoning from operational authority and now carries this separation from static checking into runtime enforcement.

## Security-qualified data

```aegis
data<string, public> banner = "hello"
data<string, confidential> telemetry = "flow"
data<string, secret> credential = "token"
secret api_key = "value"
```

Security levels form the lattice:

```text
public < confidential < secret
```

Non-public values cannot flow to `print`, modeled as a public sink.

## Tainted values

```aegis
tainted<string> user_prompt = "external content" source "user"
sanitize user_prompt as safe_prompt
print(safe_prompt)
```

`sanitize` is an explicit trusted boundary. v0.4 does not claim that the sanitization algorithm itself is formally verified.

## Evidence and trust

```aegis
evidence ioc = "203.0.113.17" trust 0.98 source "ThreatIntel"
```

Trust is in `[0.0, 1.0]`. The compiler checks trust thresholds and the runtime hashes evidence values into provenance records instead of copying raw evidence values into the audit chain.

## Capabilities

```aegis
capability propose.firewall {
    effects [write.firewall]
    risk high
}
```

A capability bounds both permissible effects and minimum declared risk.

## Models and agents

```aegis
model CyberFM {
    capabilities [classify, reason, explain]
    trust 0.97
    network none
}

agent Sentinel {
    uses CyberFM
    capabilities [propose.firewall]
    deny [shell.execute]
    trust 0.96
}
```

Agent capabilities are operational authority. Model capabilities describe AI functions and are not themselves runtime authority tokens.

## Policies

v0.4 evaluates a deliberately small, auditable policy language:

```aegis
policy MitigationPolicy {
    deny by default
    allow propose.firewall when evidence.trust >= 0.95
    deny propose.firewall when confidence < 0.90
    require human when risk == critical
}
```

Supported forms are:

```text
deny by default
allow all
allow <capability> when <expression>
deny <capability> when <expression>
require human when <expression>
```

Deny rules override allows. Runtime authorization is security-first default deny.

## Proposals

```aegis
proposal BlockHost risk high {
    by Sentinel
    capability propose.firewall
    evidence [ioc]
    min_trust 0.95
    confidence 0.99
    require confidence > 0.95
    effect write.firewall
}
```

A proposal is non-executable. High/critical proposals require evidence and at least one guard. Evidence and agent trust must satisfy `min_trust` statically; guards are evaluated again at runtime.

## Authorization and actions

```aegis
authorize BlockHost using MitigationPolicy
action QuarantineHost from BlockHost effect write.firewall capability propose.firewall reversible
```

`authorize` identifies the policy decision point. In v0.4 the named policy is evaluated at runtime.

## Capability tokens

```aegis
token FirewallToken for Sentinel capability propose.firewall ttl 300
```

The runtime issues an HMAC-SHA256 signed token containing agent, capability, issue/expiry times and a random nonce. TTL is restricted to 1..86400 seconds. Tokens are checked again immediately before execution.

## Digital Twin validation

```aegis
twin EdgeTwin {
    target production
    require availability_loss < 0.01
    require latency_delta < 5
}

validate QuarantineHost with EdgeTwin
```

Twin constraints are evaluated against runtime metrics supplied in the runtime context. An action cannot be executed unless a successful validation appears earlier in the program.

## Explicit execution

```aegis
execute QuarantineHost using FirewallToken
```

Execution requires all of the following:

1. static compilation succeeds;
2. the proposal passes its runtime guards;
3. the authorization policy allows it;
4. the capability token is valid, unexpired and matches agent/capability;
5. Digital Twin validation has passed;
6. an effect adapter accepts the action.

The default adapter is simulation-only.

## Human approval

```aegis
policy CriticalPolicy {
    deny by default
    allow identity.modify when evidence.trust >= 0.99
    require human when risk == critical
}
```

Approvals are supplied in runtime context:

```json
{"approvals": {"DisableAccount": true}}
```

## Functions, risk and effects

```aegis
fn isolate(host) risk critical {
    effects [write.firewall]
    require confidence > 0.95
    effect write.firewall
}
```

Every effect used by a function must be declared; high and critical functions require a guard.

## Intent, sequences and secure transactions

These remain first-class checked metadata:

```aegis
intent ProtectEdge {
    objective availability >= 0.9999
    constraint customer_data_exposure == 0
}

sequence BruteForce {
    event login.failed >= 10 within 30s
    followed_by login.success within 10s
}

secure transaction ContainThreat {
    action QuarantineHost
    rollback QuarantineHost
}
```

Rollback targets must be marked `reversible`.

## Compilation targets

- `python`: Python prototype backend embedding AIR 0.4 and the runtime boundary.
- `air`: Aegis Intermediate Representation 0.4 in JSON.

## Runtime command

```bash
aegis run program.aegis --context context.json --key-file /path/to/key --audit audit.json
```

## Static checks in v0.4

- security-level information flow
- taint flow and explicit sanitization
- effect declaration and capability effect envelope
- risk guards and capability minimum risk
- model/agent references
- capability grant/deny consistency
- evidence existence and trust thresholds
- policy syntax/reference validation
- proposal/action capability and effect matching
- capability-token agent/capability/TTL checks
- mandatory prior Twin validation before `execute`
- secure-transaction rollback reversibility

## Runtime checks in v0.4

- proposal guard evaluation
- policy evaluation with deny override
- human approval requirements
- HMAC capability-token verification and expiry
- Digital Twin guard evaluation
- action/token/proposal binding
- tamper-evident provenance hash-chain generation

---

# v0.4 Trust-Fabric Additions

## Asymmetric capability credentials

```aegis
credential FirewallCredential for Sentinel capability propose.firewall ttl 300 issuer "AegisAI-Lab"
```

A `credential` is an Ed25519-signed runtime authority. It is statically bound to an existing agent and capability and has the same maximum TTL rules as legacy tokens. The issuer must have a configured signing identity at runtime.

## Typed effect adapters

```aegis
adapter EdgeFirewallAdapter {
    effects [write.firewall]
    mode external
    trust_zone "edge-prod"
}
```

`mode simulation` may use the built-in no-op adapter. `mode external` requires the host runtime to bind an implementation explicitly.

Execution can select an adapter:

```aegis
execute QuarantineHost using FirewallCredential via EdgeFirewallAdapter
```

The compiler rejects an adapter whose effect set does not contain the action effect.

## Digital Twin connectors

```aegis
twin_connector EdgeTwinConnector {
    transport context
    timeout_ms 1000
}
```

Supported transports in v0.4 are `context` and `https`. HTTPS endpoints must use an `https://` URL and runtime network access remains opt-in.

A Twin binds to a connector:

```aegis
twin EdgeTwin {
    target production
    connector EdgeTwinConnector
    require availability_loss < 0.01
}
```

## Placement

```aegis
placement Sentinel at 5g {
    region "EU"
    data_residency "EU"
    max_latency_ms 10
    network "mec"
}
```

Supported environments are `cloud`, `edge`, `5g`, and `onprem`. v0.4 validates placement declarations statically and compares them with observed runtime placement telemetry.

---

# v0.5 Federated Coordination

## Capability delegation

```aegis
delegate D from Sentinel to Responder capability propose.firewall ttl 120 issuer "SOC-CA"
```

The compiler rejects delegation when the source agent does not own the capability, the target explicitly denies it, or TTL exceeds 3600 seconds.

## Quorum

```aegis
quorum Gate for BlockHost approvals 2 from [Sentinel, Responder, Analyst]
```

## Policy federation

```aegis
federation Fed {
    policies [EvidencePolicy, ConfidencePolicy]
    strategy threshold
    threshold 2
}

federate authorize BlockHost using Fed
```

## Runtime attestation

```aegis
attestation EdgeRuntime for Responder issuer "Attest-CA" max_age 300 measurement "sha256:runtime-v1"
```

## Coordinated execution

```aegis
execute QuarantineHost using ResponseDelegation via EdgeFirewallAdapter quorum Gate attestation EdgeRuntime
```

AIR compilation targets now emit version 0.5.
