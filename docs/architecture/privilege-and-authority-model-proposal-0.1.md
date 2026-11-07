# fNx Privilege and Authority Model Proposal 0.1

**Date:** 2026-11-07  
**Status:** Cross-contract authority proposal; privilege encodings, trust roots, and protocols are not ratified

## 1. Purpose

This proposal establishes a common authority vocabulary for CPU execution, workspaces, address spaces, devices, debugging, and platform management. It addresses a recurring architectural hazard: treating every privileged actor as if it possessed the same unrestricted privilege.

The model separates **execution privilege**, **resource ownership**, **delegated authority**, **debug authorization**, and **platform-management authority**. These are related but are not interchangeable.

This proposal does not select a numeric privilege-level count, mode encoding, page-table format, secure-boot protocol, or physical security mechanism.

## 2. Authority domains and principals

The architecture should distinguish at least these principals:

| Principal | Meaning | Authority source |
|---|---|---|
| Hardware thread | An executing architectural context | Current execution state and its assigned privilege |
| Workspace | A resource-sharing and protection domain | Explicit workspace policy and delegated rights |
| Address space | A translation and memory-protection domain | Translation/protection configuration controlled by an authorized principal |
| Supervisor software | OS, hypervisor, or equivalent privileged software | CPU privilege plus explicitly delegated platform capabilities |
| Device or DMA agent | An independently acting bus/fabric endpoint | Device identity, assigned mappings, and I/O permissions |
| Debug agent | A debugger, trace facility, or service processor acting in debug capacity | Separate debug authorization and policy |
| FCP | Platform control-plane processor | Authenticated platform-management authority |
| Platform trust authority | The mechanism or principal that establishes firmware and component trust | A platform-defined trust chain; implementation remains open |

A workspace is not inherently an OS process, address space, or security principal. It can carry policy and delegated capabilities, but its existence alone must not grant authority.

## 3. Separate authority dimensions

### 3.1 CPU execution privilege

CPU execution privilege controls instruction-visible operations performed by a hardware thread. At minimum, the ISA must distinguish operations that are generally available from operations that modify protected architectural state or exercise privileged control.

The architecture should define privilege predicates for operation classes rather than assume that a particular number of rings or modes is universal.

Privileged operation classes include, as applicable:

- Translation and protection configuration.
- Interrupt routing, masking, and controller configuration.
- CPU reset, halt, and power-state control.
- Global execution and debug control.
- Access to protected implementation or platform registers.
- Authority delegation and revocation.

A member may implement fewer privilege distinctions only if its declared profile preserves the required isolation and operation semantics. The minimum profile and exact privilege lattice remain open.

### 3.2 Resource ownership

Ownership answers who is responsible for a resource's lifecycle and policy. It does not automatically grant direct access to every resource operation.

Examples:
- A workspace owns its membership and shared architectural state under its policy.
- An address space owns a translation namespace and mapping lifecycle.
- A supervisor manages CPU scheduling and may manage address spaces.
- A device is identified as the requester for DMA and I/O transactions.

Ownership changes must be explicit, authorized, and serialized. Reassigning a resource must revoke stale delegated rights before the new owner can rely on exclusive control.

### 3.3 Delegated capabilities

A principal may receive a bounded capability to perform a specific action on a specific resource. A capability should identify, directly or by an unambiguous protected reference:

- Issuer and authorized holder.
- Target resource and resource generation.
- Permitted operation set.
- Scope and bounds, including address or object range where relevant.
- Relevant access attributes.
- Lifetime or revocation condition.
- Whether delegation is permitted.

Capabilities must not be forgeable by an unprivileged principal. Stale capabilities must fail after resource destruction or generation change. Delegation must not silently widen authority.

The concrete capability representation is open. It may be implemented with protected tables, tagged references, hardware-enforced capabilities, or another mechanism, provided the observable authorization contract is preserved.

### 3.4 Debug authorization

Debug authority is a separate dimension. CPU supervisor privilege must not automatically imply unrestricted external debug access, and possession of debug access must not silently grant platform-management or firmware-update authority.

The platform profile must declare:
- Which debug operations are supported.
- Who can authorize and activate a debug session.
- Whether authorization is local, physical-presence-based, cryptographic, or policy-mediated.
- What state can be inspected or modified.
- How debug access is audited and revoked.
- Behavior when debug authorization is unavailable or revoked during a session.

Production configurations may disable some debug capabilities. If disabled, attempts must fail through defined, observable behavior.

### 3.5 FCP platform-management authority

The FCP controls platform lifecycle functions such as discovery, power sequencing, reset coordination, firmware lifecycle, fault isolation, and recovery. Its authority is not a higher CPU execution mode and does not automatically confer access to application virtual memory.

FCP authority should be expressed as explicit platform-management operations over identified components and endpoints. Examples include:
- Discover and report component capabilities.
- Request reset or power-state transitions within an authorized scope.
- Isolate a failed endpoint or link.
- Coordinate boot and authenticated firmware update.
- Retrieve health and fault telemetry.
- Request a controlled debug session when platform policy permits.

The FCP must not:
- Bypass CPU memory protection to read or write arbitrary application memory.
- Forge a hardware-thread identity or impersonate a workspace.
- Change address-space mappings without an authorized platform/OS protocol.
- Weaken fabric transaction protection or atomicity.
- Convert a failed authorization into an implicit success.
- Claim that a reset or recovery completed before the affected components report the defined completion state.

An implementation may provide narrowly scoped crash-dump or recovery-memory access, but that access must be a separately specified and auditable capability with explicit lifecycle and isolation rules.

## 4. Authority checks across architectural operations

Every operation that crosses a protection boundary must have a defined authorization point and failure result.

| Operation | Required authority question |
|---|---|
| Read/write memory | Does the current thread have the requested access in the active address space? |
| Change mappings | Is the caller authorized to administer that address space, and how are stale translations invalidated? |
| Access shared workspace state | Is the thread a current member and does workspace policy permit the operation? |
| Issue DMA | Is the device identity authorized for the target address domain and range? |
| Issue fabric transaction | Are requester identity, target, operation, and attributes authorized end-to-end? |
| Configure interrupts | Is the caller authorized to alter source, target, priority, or masking policy? |
| Enter/return from trap | Is the transition target valid and is the return state protected from forgery? |
| Reset context or CPU | Does the caller hold authority for the requested reset scope? |
| Inspect/modify debug state | Is there a valid debug authorization for this component and operation? |
| Perform FCP management | Is the management principal authenticated and authorized for this platform action? |

Authorization must be checked at the boundary where the operation is accepted, and must remain valid for the operation's lifetime or be subject to a defined revocation rule. A bridge or subordinate endpoint must not trust an upstream assertion that it cannot authenticate or validate under the platform contract.

## 5. Privilege transitions and traps

The exception/trap contract must define:
- Which events may enter a more privileged execution context.
- The authorized entry targets and protected entry state.
- Which state is saved and which state is inaccessible to the caller.
- Whether and how arguments cross the boundary.
- Conditions for nested entry and interrupt delivery during entry.
- Return-state validation and permitted privilege transitions.
- Behavior for invalid or forged return state.

An unprivileged thread must not choose an arbitrary privileged return address, privilege state, address-space binding, or workspace identity. A trap is a controlled transition, not a privilege escalation API.

The architecture should permit multiple OS and hypervisor designs without embedding one syscall ABI or scheduler policy in the ISA.

## 6. DMA and fabric authority propagation

A fabric transaction must carry or resolve a trustworthy requester identity and address domain. Bridges must preserve the authorization-relevant identity and attributes across hierarchy boundaries.

DMA protection must be enforced independently of the CPU thread that configured a device. A device must not inherit the configuring thread's unrestricted memory rights.

Where translation or protection is delegated to an I/O translation unit, the contract must define:
- Device/requester identity binding.
- Mapping ownership and update authority.
- Invalidation and completion semantics.
- Fault attribution and reporting.
- Reset, reassignment, and revocation behavior.
- Isolation when the translation unit or an upstream bridge fails.

An endpoint that cannot preserve required authorization metadata must not be advertised as supporting the corresponding protected transaction class.

## 7. Revocation, teardown, and reset

Authority is not valid forever merely because it was once granted.

The contracts must define revocation behavior for:
- Workspace membership and shared-state access.
- Address-space mappings and identifiers.
- Device DMA mappings and requester identities.
- Debug sessions.
- FCP management sessions and delegated platform actions.
- Outstanding transactions issued under a revoked capability.

Revocation must define whether in-flight operations drain, complete under the old authority, abort, or report an indeterminate result. It must not silently duplicate side effects or allow new operations after the revocation point.

Destroying a workspace, address space, device assignment, or endpoint must invalidate all associated references and capabilities before an identifier can be reused. Generation-safe identity is the proposed baseline; generation width and wrap behavior remain open.

Reset must not accidentally restore revoked authority or resurrect stale capabilities. Reset cause, retained trust state, and reauthorization requirements must be specified per reset scope.

## 8. Failure behavior and audit

Authorization failures must be distinguishable from malformed operations, unavailable resources, and transport failures. The architecture must define which failures are reported synchronously to a CPU, asynchronously to a supervisor, or through the platform management plane.

Security-relevant management and debug actions should produce auditable records containing, as available:
- Principal and authenticated identity.
- Target component/resource and generation.
- Requested operation and scope.
- Authorization result and policy reference.
- Timestamp or ordered event identifier.
- Resulting state transition or failure.

Audit records must not expose protected application data merely to explain an authorization decision.

## 9. Conformance requirements

A conformance profile should declare:
- Supported CPU privilege distinctions and protected operation classes.
- Workspace and address-space ownership/delegation behavior.
- Capability or equivalent authorization mechanism.
- DMA and fabric requester-identity guarantees.
- Debug authorization capabilities and disabled states.
- FCP management operations and trust assumptions.
- Revocation, reset, and audit behavior.

Required verification includes:
1. Negative tests for every privileged operation from an unauthorized context.
2. Cross-workspace and cross-address-space isolation tests.
3. Forged, stale, revoked, and generation-mismatched capability tests.
4. DMA requester spoofing and unauthorized-range tests.
5. Bridge tests proving authorization metadata is preserved.
6. Debug access tests across enabled, disabled, and revoked states.
7. FCP/host command-conflict and unauthorized-management tests.
8. Reset and teardown tests with outstanding operations and revoked authority.
9. Differential tests confirming equivalent authorization outcomes across native widths.

A profile must not claim support for a protection feature based only on software convention when the threat model requires hardware enforcement.

## 10. Open decisions

- Minimum privilege distinctions required of every fNx member.
- Whether privilege is a strict hierarchy, a lattice, or a hybrid with orthogonal capabilities.
- Mechanism and representation for capabilities or equivalent delegated rights.
- Trust roots, secure boot, FCP authentication, firmware update, and rollback.
- Authority arbitration between host software, FCP, and external platform management.
- Debug authorization policy and production-disable requirements.
- DMA/I/O translation architecture and requester identity format.
- Revocation points and treatment of in-flight operations.
- Audit retention, ordering, and tamper resistance.
- Exact architectural fault codes and reporting paths.

## 11. Related specifications

- [fNx exception, trap, and interrupt model](exception-and-interrupt-model-proposal-0.1.md)
- [fNx control processor and management plane](fnx-control-and-management-plane-0.1.md)
- [Workspace and thread lifecycle contract](workspace-and-thread-lifecycle-contract-proposal-0.1.md)
- [Address-space and memory-model proposal](address-space-and-memory-model-proposal-0.1.md)
- [Width-neutral fabric and backplane contract](width-neutral-fabric-and-backplane-contract-proposal-0.1.md)
- [M1 requirements traceability matrix](m1-requirements-traceability-matrix-0.1.md)
- [Conformance and reference-model strategy](conformance-and-reference-model-strategy-0.1.md)
