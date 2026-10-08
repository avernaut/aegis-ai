# AegisAI Language Draft v0.1

AegisAI is an experimental language for **bounded autonomous intelligence**. The compiler treats security, risk, policy and effects as language semantics rather than library conventions.

## Core declarations

```aegis
data<string, public> banner = "hello"
data<string, confidential> telemetry = "flow"
data<string, secret> credential = "token"
secret api_key = "value"
```

Security levels form the lattice:

`public < confidential < secret`

The v0.1 compiler forbids non-public data from flowing to `print`, which is modeled as a public sink.

## Requirements

```aegis
require confidence > 0.95
```

`require` is a runtime guard and also contributes to static risk validation. High- and critical-risk functions require at least one explicit guard.

## Functions, risk and effects

```aegis
fn isolate(host) risk critical {
    effects [write.firewall]
    require confidence > 0.95
    effect write.firewall
}
```

Every effect used in a function must be declared in its `effects` set.

## Policies

```aegis
policy ZeroTrust {
    deny by default
    allow network.access when identity.verified
}
```

In v0.1 policies are preserved in AIR and target output. Policy evaluation is planned for v0.2.

## Calls

```aegis
call investigate("flow-42")
```

## Compilation targets

- `python`: executable prototype backend.
- `air`: Aegis Intermediate Representation in JSON.

## Planned syntax

Future versions will add first-class `agent`, `model`, `proposal`, `authorize`, `action`, `twin`, `evidence`, `trust`, `tainted`, temporal `sequence`, secure transactions and capability-scoped execution.
