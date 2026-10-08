# AegisAI v0.2 Compiler Architecture

```text
AegisAI source
    |
    v
logical lexer
    |
    v
parser -----------------------------> AST
                                       |
                                       v
                              static semantic checker
                              - information flow
                              - taint boundaries
                              - risk guards
                              - effect declarations
                              - model/agent links
                              - capability checks
                              - evidence/trust checks
                              - authorization gates
                              - action consistency
                              - transaction rollback
                                       |
                       +---------------+----------------+
                       |                                |
                       v                                v
                 AIR v0.2 JSON                   Python backend
                       |
                       v
        future policy/runtime enforcement layer
```

## Core design invariant

**Reasoning authority is not execution authority.**

The compiler models this explicitly:

```text
Model -> Agent -> Proposal -> Authorization -> Action
                    ^              ^             |
                    |              |             v
              Evidence/Trust     Policy       Effects
```

An AI agent can produce a proposal only inside its capability envelope. The proposal carries risk, evidence, guards, declared effects and a minimum trust level. An action is valid only after explicit authorization.

## AIR v0.2

AIR is a JSON-based intermediate representation carrying security metadata rather than erasing it during compilation. Important operations include:

- `capability.declare`
- `ai.model`
- `ai.agent`
- `evidence.declare`
- `ai.proposal`
- `auth.authorize`
- `action.declare`
- `taint.declare`
- `taint.sanitize`
- `twin.declare`
- `intent.declare`
- `sequence.declare`
- `transaction.secure`

Future backends can therefore consume the same checked security semantics for WASM, eBPF, Kubernetes admission, policy engines or Edge runtimes.

## v0.3 research targets

- typed expressions and structured boolean conditions
- executable policy engine with deny-overrides semantics
- provenance DAG and cryptographic audit records
- capability tokens for runtime tool invocation
- digital-twin adapter interface and simulation result types
- explicit `execute` statement with runtime authorization token
- reversible-action compensation functions
- WASM-oriented AIR lowering
- deployment/placement constraints for Cloud/Edge/5G/6G
- formal small-step operational semantics
