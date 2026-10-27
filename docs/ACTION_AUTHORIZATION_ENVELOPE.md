# Action Authorization Envelope (AAE)

Status: Proposed for AegisAI v0.6.0

## 1. Purpose

The Action Authorization Envelope is the execution contract between an AegisAI agent and a privileged infrastructure tool. It makes authority explicit at the moment an action is proposed and prevents an agent from relying on implicit prompt context or broad tool permissions.

An AAE is intentionally small. It does not contain the agent's private chain of thought. Instead, it contains only operationally relevant evidence and enforceable constraints.

## 2. Core principle

> An agent may propose an action, but an execution gateway must validate the envelope before allowing the action to reach infrastructure.

The gateway must not infer missing authority. Missing mandatory fields are a denial condition.

## 3. Execution flow

1. **Observe** — the agent collects telemetry and evidence.
2. **Decide** — the agent proposes an action.
3. **Build envelope** — the agent/runtime binds action, target, authority, policy, risk, and evidence.
4. **Verify** — independent controls evaluate authorization, scope, attestation, quorum, policy, safety checks, and evidence freshness.
5. **Act** — the gateway executes only if the envelope is valid.
6. **Validate** — the system checks outcome and records provenance.
7. **Revoke / recover** — authority can be withdrawn and rollback attempted when supported.

## 4. Envelope fields

### Identity

- `envelope_id`: globally unique identifier.
- `agent_id`: stable identity of the requesting agent.
- `issued_at`: UTC timestamp.
- `expires_at`: UTC timestamp after which execution must be denied.

### Proposed action

- `action.type`: normalized action name.
- `action.target`: target resource identifier.
- `action.parameters`: action-specific arguments.

### Authority

- `authority.scope`: resources/actions the agent is permitted to affect.
- `authority.delegated_by`: optional parent authority.
- `authority.delegation_depth`: bounded delegation depth.
- `authority.revocable`: whether the capability can be externally revoked.

### Risk and approval

- `risk.level`: `low`, `medium`, `high`, or `critical`.
- `approval.mode`: `automatic`, `quorum`, or `human`.
- `approval.quorum_required`: minimum independent approvals when applicable.

### Policy and attestation

- `policy.policy_set`: policy bundle identifier.
- `policy.policy_version`: immutable version/hash reference.
- `attestation.required`: whether runtime attestation is mandatory.
- `attestation.measurement`: optional runtime measurement reference.

### Verification

- `verification.required_checks`: named checks that must pass.
- `verification.max_age_seconds`: maximum age of evidence used by verification.
- `verification.digital_twin_required`: whether simulation is mandatory.

### Recovery and provenance

- `recovery.rollback_supported`: whether the action is designed to be reversible.
- `recovery.rollback_action`: optional compensating action.
- `provenance.evidence_refs`: references to telemetry or incident evidence.
- `provenance.correlation_id`: identifier linking detection, decision, verification, and execution.

## 5. Mandatory denial conditions

The gateway must deny execution when any of the following is true:

- the envelope is expired;
- the target or action lies outside `authority.scope`;
- `delegation_depth` exceeds policy limits;
- required quorum is not satisfied;
- a required policy/attestation/verification field is missing;
- evidence is older than `verification.max_age_seconds`;
- a required check has failed;
- the capability has been revoked;
- a critical/high-risk action requires human approval and none is present.

## 6. Risk-adaptive defaults

| Risk | Default approval | Suggested checks |
|---|---|---|
| Low | automatic | authorization, scope, policy |
| Medium | automatic or quorum | authorization, target correctness, policy, blast radius |
| High | quorum | all medium checks + availability, reachability, rollback readiness, optional digital twin |
| Critical | human + quorum | full verification, fresh attestation, digital twin where available, explicit recovery plan |

These are defaults, not universal guarantees. Deployments should override them through policy.

## 7. Security properties

AAE is intended to improve:

- **least authority** — execution is scoped to a concrete action and target;
- **auditability** — each privileged action has a stable envelope identifier;
- **revocability** — permission can be invalidated outside the agent;
- **provenance** — evidence references are attached without exposing hidden reasoning;
- **policy determinism** — the execution gateway evaluates explicit fields rather than natural-language intent;
- **fail-safe behavior** — missing or stale evidence causes denial rather than implicit approval.

## 8. Non-goals

AAE does not prove that an AI decision is correct. It does not replace policy engines, digital twins, runtime attestation, human oversight, or post-action monitoring. It is a transport and enforcement contract connecting those mechanisms.

## 9. Recommended implementation sequence

1. Land the JSON Schema and examples.
2. Add runtime validation before every privileged tool call.
3. Introduce policy adapters for risk/approval decisions.
4. Add revocation lookup to the execution gateway.
5. Add provenance logging keyed by `envelope_id` and `correlation_id`.
6. Add negative tests for stale, out-of-scope, revoked, and under-approved envelopes.
