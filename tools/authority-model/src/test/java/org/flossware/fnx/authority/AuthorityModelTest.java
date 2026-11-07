package org.flossware.fnx.authority;

import java.util.EnumSet;
import java.util.Set;

import org.flossware.fnx.authority.AuthorityModel.Capability;
import org.flossware.fnx.authority.AuthorityModel.Decision;
import org.flossware.fnx.authority.AuthorityModel.DenialReason;
import org.flossware.fnx.authority.AuthorityModel.Operation;
import org.flossware.fnx.authority.AuthorityModel.Principal;
import org.flossware.fnx.authority.AuthorityModel.PrincipalKind;
import org.flossware.fnx.authority.AuthorityModel.Resource;
import org.flossware.fnx.authority.AuthorityModel.ResourceKind;

/** Deterministic executable checks for the authority reference model. */
public final class AuthorityModelTest {
    private static final Principal ROOT =
            new Principal("platform-root", PrincipalKind.PLATFORM_AUTHORITY);
    private static final Principal WORKSPACE_OWNER =
            new Principal("workspace-owner", PrincipalKind.OS_SUPERVISOR);
    private static final Principal THREAD =
            new Principal("thread-17", PrincipalKind.THREAD);
    private static final Principal OTHER_THREAD =
            new Principal("thread-18", PrincipalKind.THREAD);
    private static final Principal FCP =
            new Principal("fcp-0", PrincipalKind.FCP);
    private static final Principal DEBUGGER =
            new Principal("debug-agent-0", PrincipalKind.DEBUG_AGENT);
    private static final Principal DEVICE =
            new Principal("device-3", PrincipalKind.DEVICE);

    private AuthorityModelTest() {
    }

    public static void main(String[] args) {
        Resource memory = new Resource("memory-0", 1,
                ResourceKind.MEMORY, WORKSPACE_OWNER.id(), 4096);
        Resource component = new Resource("cpu-0", 1,
                ResourceKind.PLATFORM_COMPONENT, "platform-root", 1);
        Resource workspace = new Resource("workspace-4", 1,
                ResourceKind.WORKSPACE_STATE, WORKSPACE_OWNER.id(), 256);
        AuthorityModel model = new AuthorityModel(Set.of(ROOT.id()));
        model.registerResource(memory);
        model.registerResource(component);
        model.registerResource(workspace);

        expect(model.authorize(THREAD, memory, Operation.READ_MEMORY,
                100, 4, null), DenialReason.MISSING_CAPABILITY,
                "workspace membership is not an implicit memory capability");

        expectThrows(SecurityException.class,
                () -> model.issueCapability(WORKSPACE_OWNER, THREAD, memory,
                        EnumSet.of(Operation.READ_MEMORY), 100, 200),
                "resource ownership does not automatically grant delegation authority");

        Capability boundedRead = model.issueCapability(ROOT, THREAD, memory,
                EnumSet.of(Operation.READ_MEMORY), 100, 200);
        expectAllowed(model.authorize(THREAD, memory, Operation.READ_MEMORY,
                100, 16, boundedRead), "granted memory read");
        expect(model.authorize(THREAD, memory, Operation.WRITE_MEMORY,
                100, 16, boundedRead), DenialReason.OPERATION_NOT_GRANTED,
                "read grant does not imply write");
        expect(model.authorize(THREAD, memory, Operation.READ_MEMORY,
                190, 16, boundedRead), DenialReason.RANGE_NOT_GRANTED,
                "memory grant is bounded");

        Capability fcpReset = model.issueCapability(ROOT, FCP, component,
                EnumSet.of(Operation.RESET_COMPONENT), 0, 1);
        expectAllowed(model.authorize(FCP, component, Operation.RESET_COMPONENT,
                0, 0, fcpReset), "explicit FCP reset grant");
        expect(model.authorize(FCP, memory, Operation.READ_MEMORY,
                100, 4, fcpReset), DenialReason.WRONG_RESOURCE,
                "FCP management grant does not imply application-memory access");

        Capability debugInspect = model.issueCapability(ROOT, DEBUGGER, component,
                EnumSet.of(Operation.DEBUG_INSPECT), 0, 1);
        expectAllowed(model.authorize(DEBUGGER, component, Operation.DEBUG_INSPECT,
                0, 0, debugInspect), "explicit debug inspection grant");
        expect(model.authorize(DEBUGGER, component, Operation.DEBUG_MODIFY,
                0, 0, debugInspect), DenialReason.OPERATION_NOT_GRANTED,
                "debug inspection does not imply debug modification");

        Capability dmaRead = model.issueCapability(ROOT, DEVICE, memory,
                EnumSet.of(Operation.DMA_READ), 512, 768);
        expectAllowed(model.authorize(DEVICE, memory, Operation.DMA_READ,
                512, 128, dmaRead), "DMA read inside assigned mapping");
        expect(model.authorize(DEVICE, memory, Operation.DMA_READ,
                700, 128, dmaRead), DenialReason.RANGE_NOT_GRANTED,
                "DMA cannot escape assigned mapping");
        expect(model.authorize(THREAD, memory, Operation.DMA_READ,
                512, 16, dmaRead), DenialReason.WRONG_HOLDER,
                "DMA capability is bound to requester identity");

        model.revoke(boundedRead);
        expect(model.authorize(THREAD, memory, Operation.READ_MEMORY,
                100, 4, boundedRead), DenialReason.REVOKED_CAPABILITY,
                "revoked capability is denied");

        Capability stale = model.issueCapability(ROOT, THREAD, workspace,
                EnumSet.of(Operation.ACCESS_SHARED_STATE), 0, 64);
        Resource replacement = new Resource("workspace-4", 2,
                ResourceKind.WORKSPACE_STATE, WORKSPACE_OWNER.id(), 256);
        model.registerResource(replacement);
        expect(model.authorize(THREAD, replacement, Operation.ACCESS_SHARED_STATE,
                0, 8, stale), DenialReason.STALE_RESOURCE_GENERATION,
                "resource generation change invalidates stale capability");

        expect(model.authorize(OTHER_THREAD, memory, Operation.READ_MEMORY,
                100, 4, dmaRead), DenialReason.WRONG_HOLDER,
                "capability cannot be used by another principal");

        System.out.println("PASS: authority reference model checks");
    }

    private static void expect(Decision decision, DenialReason expected,
            String label) {
        if (decision.allowed() || decision.reason() != expected) {
            throw new AssertionError(label + ": expected denial " + expected
                    + " but received " + decision);
        }
    }

    private static void expectAllowed(Decision decision, String label) {
        if (!decision.allowed()) {
            throw new AssertionError(label + ": expected allow but received " + decision);
        }
    }

    private static void expectThrows(Class<? extends Throwable> expected,
            Runnable action, String label) {
        try {
            action.run();
        } catch (Throwable actual) {
            if (expected.isInstance(actual)) {
                return;
            }
            throw new AssertionError(label + ": wrong exception " + actual, actual);
        }
        throw new AssertionError(label + ": expected " + expected.getSimpleName());
    }
}
