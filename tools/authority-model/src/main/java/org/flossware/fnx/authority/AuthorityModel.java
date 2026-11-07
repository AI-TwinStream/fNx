package org.flossware.fnx.authority;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Small executable reference model for the proposed fNx authority contract.
 *
 * This models authorization outcomes, not cryptography, hardware isolation,
 * secure storage, or a production capability implementation. The trust root
 * for issuers is supplied by the test/platform configuration.
 */
public final class AuthorityModel {
    public enum PrincipalKind {
        THREAD,
        WORKSPACE,
        OS_SUPERVISOR,
        DEVICE,
        DEBUG_AGENT,
        FCP,
        PLATFORM_AUTHORITY
    }

    public enum ResourceKind {
        MEMORY,
        WORKSPACE_STATE,
        DEVICE,
        CPU_UNIT,
        PLATFORM_COMPONENT
    }

    public enum Operation {
        READ_MEMORY,
        WRITE_MEMORY,
        ACCESS_SHARED_STATE,
        DMA_READ,
        DMA_WRITE,
        DEBUG_INSPECT,
        DEBUG_MODIFY,
        RESET_COMPONENT,
        UPDATE_FIRMWARE,
        MANAGE_ENDPOINT
    }

    public enum DenialReason {
        NONE,
        MISSING_CAPABILITY,
        UNTRUSTED_ISSUER,
        REVOKED_CAPABILITY,
        WRONG_HOLDER,
        WRONG_RESOURCE,
        STALE_RESOURCE_GENERATION,
        OPERATION_NOT_GRANTED,
        RANGE_NOT_GRANTED,
        UNKNOWN_RESOURCE
    }

    public record Principal(String id, PrincipalKind kind) {
        public Principal {
            requireText(id, "principal id");
            Objects.requireNonNull(kind, "kind");
        }
    }

    /**
     * ownerId is lifecycle/policy metadata. It does not grant access by itself.
     */
    public record Resource(String id, long generation, ResourceKind kind,
            String ownerId, long size) {
        public Resource {
            requireText(id, "resource id");
            Objects.requireNonNull(kind, "kind");
            requireText(ownerId, "owner id");
            if (generation < 0) {
                throw new IllegalArgumentException("generation must be non-negative");
            }
            if (size <= 0) {
                throw new IllegalArgumentException("size must be positive");
            }
        }
    }

    public record Decision(boolean allowed, DenialReason reason) {
        public Decision {
            Objects.requireNonNull(reason, "reason");
            if (allowed != (reason == DenialReason.NONE)) {
                throw new IllegalArgumentException("allowed and reason disagree");
            }
        }
    }

    /**
     * An opaque, immutable authorization grant issued by this model.
     * Construction is private so callers cannot manufacture a grant value.
     */
    public static final class Capability {
        private final long id;
        private final String holderId;
        private final String resourceId;
        private final long resourceGeneration;
        private final Set<Operation> operations;
        private final long rangeStart;
        private final long rangeEnd;

        private Capability(long id, String holderId, Resource resource,
                Set<Operation> operations, long rangeStart, long rangeEnd) {
            this.id = id;
            this.holderId = holderId;
            this.resourceId = resource.id();
            this.resourceGeneration = resource.generation();
            this.operations = Set.copyOf(operations);
            this.rangeStart = rangeStart;
            this.rangeEnd = rangeEnd;
        }
    }

    private final Set<String> trustedIssuerIds;
    private final Map<String, Resource> resources = new HashMap<>();
    private final Set<Long> revokedCapabilityIds = new HashSet<>();
    private long nextCapabilityId = 1;

    /**
     * The caller supplies the trusted issuer set. Establishing and protecting
     * that trust root is deliberately outside this abstract reference model.
     */
    public AuthorityModel(Set<String> trustedIssuerIds) {
        Objects.requireNonNull(trustedIssuerIds, "trustedIssuerIds");
        this.trustedIssuerIds = Set.copyOf(trustedIssuerIds);
        if (this.trustedIssuerIds.isEmpty()) {
            throw new IllegalArgumentException("at least one trusted issuer is required");
        }
        this.trustedIssuerIds.forEach(id -> requireText(id, "trusted issuer id"));
    }

    public void registerResource(Resource resource) {
        Objects.requireNonNull(resource, "resource");
        Resource previous = resources.get(resource.id());
        if (previous != null && resource.generation() <= previous.generation()) {
            throw new IllegalArgumentException(
                    "replacement resource generation must increase");
        }
        resources.put(resource.id(), resource);
    }

    /**
     * Issues an explicit, holder-bound grant over one resource generation and
     * a half-open range [rangeStart, rangeEnd). Ownership alone is not enough:
     * only an issuer configured as trusted may delegate authority.
     */
    public Capability issueCapability(Principal issuer, Principal holder,
            Resource resource, Set<Operation> operations,
            long rangeStart, long rangeEnd) {
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(holder, "holder");
        Objects.requireNonNull(resource, "resource");
        Objects.requireNonNull(operations, "operations");
        if (!trustedIssuerIds.contains(issuer.id())) {
            throw new SecurityException("issuer is not trusted");
        }
        Resource current = resources.get(resource.id());
        if (!resource.equals(current)) {
            throw new IllegalArgumentException("resource is not the current registered generation");
        }
        if (operations.isEmpty() || operations.contains(null)) {
            throw new IllegalArgumentException("at least one valid operation is required");
        }
        if (rangeStart < 0 || rangeEnd <= rangeStart || rangeEnd > resource.size()) {
            throw new IllegalArgumentException("capability range is outside the resource");
        }
        Capability capability = new Capability(nextCapabilityId++,
                holder.id(), resource, operations, rangeStart, rangeEnd);
        return capability;
    }

    public void revoke(Capability capability) {
        Objects.requireNonNull(capability, "capability");
        revokedCapabilityIds.add(capability.id);
    }

    public Decision authorize(Principal requester, Resource resource,
            Operation operation, long offset, long length,
            Capability capability) {
        Objects.requireNonNull(requester, "requester");
        Objects.requireNonNull(resource, "resource");
        Objects.requireNonNull(operation, "operation");
        if (capability == null) {
            return deny(DenialReason.MISSING_CAPABILITY);
        }
        if (revokedCapabilityIds.contains(capability.id)) {
            return deny(DenialReason.REVOKED_CAPABILITY);
        }
        if (!capability.holderId.equals(requester.id())) {
            return deny(DenialReason.WRONG_HOLDER);
        }
        if (!capability.resourceId.equals(resource.id())) {
            return deny(DenialReason.WRONG_RESOURCE);
        }
        Resource current = resources.get(resource.id());
        if (current == null) {
            return deny(DenialReason.UNKNOWN_RESOURCE);
        }
        if (!resource.equals(current)
                || capability.resourceGeneration != current.generation()) {
            return deny(DenialReason.STALE_RESOURCE_GENERATION);
        }
        if (!capability.operations.contains(operation)) {
            return deny(DenialReason.OPERATION_NOT_GRANTED);
        }
        if (offset < capability.rangeStart || length < 0
                || offset > capability.rangeEnd
                || length > capability.rangeEnd - offset) {
            return deny(DenialReason.RANGE_NOT_GRANTED);
        }
        return new Decision(true, DenialReason.NONE);
    }

    private static Decision deny(DenialReason reason) {
        return new Decision(false, reason);
    }

    private static void requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be blank");
        }
    }
}
