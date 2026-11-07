# fNx Authority Reference Model 0.1

**Status:** Executable semantic prototype for the privilege/authority proposal. It is not a security implementation or a ratified architectural contract.

## Purpose

This small Java model makes selected authority rules executable before the architecture chooses a concrete capability encoding or privilege hierarchy.

It currently exercises:

- Explicit, holder-bound grants.
- Resource and generation binding.
- Operation-specific authorization.
- Bounded resource ranges.
- Revocation.
- Distinct CPU-thread, device, debugger, FCP, supervisor, and platform-authority principals.
- No implicit access from resource ownership or principal kind.
- No implicit widening from debug inspection to debug modification.
- No implicit widening from FCP component management to unrelated resource access.

The model deliberately does **not** decide:
- How a hardware or software trust root is established.
- How capabilities are represented, stored, authenticated, or protected against physical tampering.
- Which architectural privilege levels every fNx member must implement.
- Which principal is entitled to issue each production capability.
- How in-flight transactions are drained or aborted at revocation.
- The memory consistency model, trap ABI, or FCP firmware protocol.

Those remain architectural decisions. This prototype is a semantic test bed, not a clever way to smuggle them into the standard.

## Build and run

Requires JDK 25 or newer. There are no third-party dependencies.

From the repository root:

```sh
mkdir -p build/authority-model
javac --release 25 -Xlint:all -Werror \
  -d build/authority-model \
  tools/authority-model/src/main/java/org/flossware/fnx/authority/AuthorityModel.java
javac --release 25 -Xlint:all -Werror -cp build/authority-model \
  -d build/authority-model \
  tools/authority-model/src/test/java/org/flossware/fnx/authority/AuthorityModelTest.java
java -cp build/authority-model org.flossware.fnx.authority.AuthorityModelTest
```

Expected output:

```
PASS: authority reference model checks
```

## Relationship to the architecture

The model is derived from:
- [Privilege and authority model proposal](../../docs/architecture/privilege-and-authority-model-proposal-0.1.md)
- [M1 requirements traceability matrix](../../docs/architecture/m1-requirements-traceability-matrix-0.1.md)

The test cases are proposal-level evidence for CTRL-007 through CTRL-010 and related MEM/FAB authorization requirements. They do not constitute conformance evidence for a hardware implementation.
