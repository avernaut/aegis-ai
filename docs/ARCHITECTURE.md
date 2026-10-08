# Compiler Architecture

```text
AegisAI source
    |
    v
logical lexer
    |
    v
parser -> AST
    |
    v
static checker
  - security-flow checking
  - effect checking
  - risk guards
  - symbol validation
    |
    +--------------------+
    |                    |
    v                    v
Aegis IR (AIR)       Python backend
```

## Design principle

The compiler separates **reasoning power** from **execution authority**. Future backends will preserve this distinction through capability tokens and policy-mediated execution.

## Roadmap

### v0.2
- typed expressions
- assignments and control flow
- policy evaluator
- taint tracking
- trust-annotated values
- source/sink information-flow graph

### v0.3
- `model` and `agent` declarations
- capability system
- proposals and authorization gates
- evidence/provenance graph

### v0.4
- digital-twin validation primitives
- reversible actions
- secure transactions
- eBPF/WASM-oriented AIR lowering

### v1.0 research target
- formal small-step semantics
- proof-oriented policy checks
- capability-safe AI tool execution
- distributed Cloud/Edge/5G deployment constraints
