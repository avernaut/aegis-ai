# AegisAI v0.3 Runtime

The runtime turns checked AIR 0.3 into a bounded-authority decision pipeline.

## Running a program

```bash
aegis run examples/bounded_defense.aegis \
  --context examples/runtime_context.json \
  --key-file /path/to/runtime.key \
  --audit /tmp/aegis-audit.json
```

The key must contain at least 16 bytes. It is never stored in AIR or source code.

## Runtime order

For every executable path, the runtime processes:

```text
proposal guards
    -> policy decision
    -> capability token issuance
    -> Digital Twin validation
    -> token verification
    -> effect adapter
    -> provenance event
```

The source order of `validate` and `execute` is statically checked.

## Context schema

The context is intentionally open but the current runtime recognizes:

```json
{
  "proposals": {
    "ProposalName": {"confidence": 0.98}
  },
  "approvals": {
    "ProposalName": true
  },
  "twins": {
    "TwinName": {
      "metric": 0.0
    }
  }
}
```

## Safe expression evaluator

Policy and Twin expressions are parsed as expression ASTs. General Python calls, imports, indexing, comprehensions, lambdas and attribute access outside supplied dictionaries are rejected.

## Effect adapters

The interface is intentionally small:

```python
class EffectAdapter(Protocol):
    def execute(self, action: dict, context: dict) -> dict: ...
```

The bundled `NoOpAdapter` performs no external action. Applications may inject their own adapter through the Python API, but production adapters are outside the trust claims of v0.3.

## Python API

```python
from aegisai import run_source

result = run_source(
    source,
    context=context,
    runtime_key=key,
)

print(result.to_dict())
```

## Audit verification

```bash
aegis verify-audit /tmp/aegis-audit.json
```

Any modification of an entry's payload, sequence, timestamp, previous hash or hash makes the chain invalid.
