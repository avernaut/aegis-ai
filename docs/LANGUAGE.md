# AegisAI Language Draft v0.2

AegisAI is an experimental language for **bounded autonomous intelligence**. v0.2 makes security levels, taint, AI models, autonomous agents, trust, evidence, capabilities, proposals, authorization, actions, intents, digital twins and secure transactions explicit language concepts.

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

Non-public values cannot flow to `print`, which is modeled as a public sink.

## Tainted values

```aegis
tainted<string> user_prompt = "external content" source "user"
```

A tainted value cannot flow directly to a public sink. v0.2 introduces an explicit sanitization boundary:

```aegis
sanitize user_prompt as safe_prompt
print(safe_prompt)
```

The current prototype treats `sanitize` as a trusted boundary. Future versions will bind sanitizers to typed validation functions.

## Evidence and trust

```aegis
evidence ioc = "203.0.113.17" trust 0.98 source "ThreatIntel"
```

Trust is a floating-point value in `[0.0, 1.0]` and is preserved in AIR.

## Capabilities

Operational authority can be declared explicitly:

```aegis
capability propose.firewall {
    effects [write.firewall]
    risk high
}
```

When capability declarations are present, agent grants must reference declared capabilities. Proposal effects cannot exceed the capability effect set, and proposal risk cannot understate the capability minimum risk.

## Models

```aegis
model CyberFM {
    capabilities [classify, reason, explain]
    trust 0.97
    network none
}
```

`network none` expresses intended network isolation as metadata in v0.2.

## Agents and capabilities

```aegis
agent Sentinel {
    uses CyberFM
    capabilities [read.telemetry, read.threat_intel, propose.firewall]
    deny [shell.execute, identity.modify]
    trust 0.96
}
```

A capability simultaneously present in `capabilities` and `deny` is rejected. A proposal cannot use an absent or denied capability.

## Policies

```aegis
policy ZeroTrust {
    deny by default
    allow network.access when identity.verified
}
```

v0.2 validates policy references during authorization and preserves policy rules in AIR. Rule evaluation itself remains a planned runtime/compiler feature.

## Proposals

```aegis
proposal BlockHost risk high {
    by Sentinel
    capability propose.firewall
    evidence [ioc]
    min_trust 0.95
    require confidence > 0.95
    effect write.firewall
}
```

A high/critical-risk proposal requires both an explicit guard and evidence. Every evidence item and the proposing agent must satisfy `min_trust`.

A proposal is **not executable**. It represents an AI recommendation awaiting authority.

## Authorization and actions

```aegis
authorize BlockHost using MitigationPolicy
action QuarantineHost from BlockHost effect write.firewall capability propose.firewall reversible
```

An action must derive from an authorized proposal. Its capability must match the proposal capability, and its effect must have been declared by that proposal.

## Functions, risk and effects

```aegis
fn isolate(host) risk critical {
    effects [write.firewall]
    require confidence > 0.95
    effect write.firewall
}
```

Every effect used by a function must be explicitly declared. High- and critical-risk functions require at least one guard.

## Digital twin declarations

```aegis
twin EdgeTwin {
    target production
    require availability_loss < 0.01
    require latency_delta < 5
}
```

v0.2 preserves twin validation constraints in AIR. A later runtime will evaluate them against a concrete twin adapter.

## Intent-oriented declarations

```aegis
intent ProtectEdge {
    objective availability >= 0.9999
    objective intrusion_risk < 0.01
    constraint customer_data_exposure == 0
}
```

Intents describe objectives and hard constraints rather than a procedural implementation.

## Temporal sequences

```aegis
sequence BruteForce {
    event login.failed >= 10 within 30s
    followed_by login.success within 10s
}
```

v0.2 captures sequence semantics as ordered AIR metadata. Temporal execution is planned for a dedicated runtime.

## Secure transactions

```aegis
secure transaction ContainThreat {
    action QuarantineHost
    rollback QuarantineHost
}
```

A rollback target must exist and be declared `reversible`.

## Calls

```aegis
call investigate("flow-42")
```

## Compilation targets

- `python`: prototype executable/metadata backend.
- `air`: Aegis Intermediate Representation v0.2 in JSON.

## Static checks in v0.2

- secret/confidential -> public sink rejection
- tainted -> public sink rejection
- explicit sanitization boundary
- function effect declaration
- risk guards
- model/agent references
- capability allow/deny consistency
- proposal capability ownership
- evidence existence
- agent/evidence trust threshold enforcement
- authorization reference validation
- action/proposal capability/effect matching
- secure-transaction rollback reversibility
