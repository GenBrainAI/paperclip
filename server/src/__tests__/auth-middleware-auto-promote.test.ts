import { describe, expect, it, vi, beforeEach } from "vitest";

/**
 * Tests that the auth middleware auto-promotes the first authenticated user
 * to instance_admin when no real admin exists. This catches the race where
 * BetterAuth's signup hook hasn't committed the role yet.
 */

vi.mock("node:crypto", () => ({
  createHash: () => ({ update: () => ({ digest: () => "mockhash" }) }),
}));

vi.mock("../agent-auth-jwt.js", () => ({
  verifyLocalAgentJwt: () => null,
}));

vi.mock("./logger.js", () => ({
  logger: { warn: vi.fn(), info: vi.fn() },
}));

vi.mock("@paperclipai/db", () => ({
  instanceUserRoles: { id: "id", userId: "userId", role: "role" },
  companyMemberships: {
    companyId: "companyId",
    principalType: "principalType",
    principalId: "principalId",
    status: "status",
  },
  agentApiKeys: { keyHash: "keyHash", revokedAt: "revokedAt", id: "id" },
  agents: { id: "id" },
}));

vi.mock("drizzle-orm", () => ({
  eq: vi.fn((_col: unknown, val: unknown) => val),
  and: vi.fn((...args: unknown[]) => args),
  isNull: vi.fn(),
}));

// Track which table is being queried
let roleSelectResult: unknown[] = [];
let allAdminsResult: Array<{ userId: string }> = [];
let membershipSelectResult: unknown[] = [];
let roleSelectCallCount = 0;
const mockInsertValues = vi.fn();

function createMockDb() {
  roleSelectCallCount = 0;
  return {
    select: vi.fn().mockImplementation((fields?: Record<string, unknown>) => {
      const hasUserId = fields && "userId" in fields;
      const hasCompanyId = fields && "companyId" in fields;
      return {
        from: vi.fn().mockReturnValue({
          where: vi.fn().mockImplementation(() => {
            if (hasCompanyId) {
              // companyMemberships query
              return Promise.resolve(membershipSelectResult);
            }
            // instanceUserRoles queries
            roleSelectCallCount++;
            if (roleSelectCallCount === 1) {
              // First: check if this user has instance_admin
              return { then: (fn: (rows: unknown[]) => unknown) => Promise.resolve(fn(roleSelectResult)) };
            }
            // Second: list all admins for auto-promote check
            return Promise.resolve(allAdminsResult);
          }),
        }),
      };
    }),
    insert: vi.fn().mockReturnValue({
      values: mockInsertValues.mockReturnValue(Promise.resolve()),
    }),
  };
}

const { actorMiddleware } = await import("../middleware/auth.js");

describe("actorMiddleware — first-user auto-promotion", () => {
  let mockDb: ReturnType<typeof createMockDb>;
  const mockResolveSession = vi.fn();

  function createRequest(headers: Record<string, string> = {}) {
    return {
      actor: { type: "none", source: "none" },
      header: (name: string) => headers[name.toLowerCase()] ?? undefined,
      headers,
      method: "GET",
      originalUrl: "/",
    } as unknown as import("express").Request;
  }

  beforeEach(() => {
    vi.clearAllMocks();
    roleSelectResult = [];
    allAdminsResult = [];
    membershipSelectResult = [];
    mockDb = createMockDb();
  });

  it("auto-promotes first user when no admins exist", async () => {
    mockResolveSession.mockResolvedValue({
      user: { id: "user-1", email: "test@example.com", name: "Test" },
      session: { id: "sess-1", userId: "user-1" },
    });
    roleSelectResult = []; // user is NOT yet an admin
    allAdminsResult = []; // NO admins at all

    const middleware = actorMiddleware(mockDb as any, {
      deploymentMode: "authenticated",
      resolveSession: mockResolveSession,
    });
    const req = createRequest();
    const next = vi.fn();
    await middleware(req, {} as any, next);

    expect(next).toHaveBeenCalled();
    expect(req.actor.type).toBe("board");
    expect((req.actor as any).isInstanceAdmin).toBe(true);
    expect(mockInsertValues).toHaveBeenCalledWith({
      userId: "user-1",
      role: "instance_admin",
    });
  });

  it("does NOT auto-promote when a real admin already exists", async () => {
    mockResolveSession.mockResolvedValue({
      user: { id: "user-2", email: "new@example.com", name: "New" },
      session: { id: "sess-2", userId: "user-2" },
    });
    roleSelectResult = []; // user-2 is NOT admin
    allAdminsResult = [{ userId: "user-1" }]; // user-1 is already admin

    const middleware = actorMiddleware(mockDb as any, {
      deploymentMode: "authenticated",
      resolveSession: mockResolveSession,
    });
    const req = createRequest();
    const next = vi.fn();
    await middleware(req, {} as any, next);

    expect(next).toHaveBeenCalled();
    expect((req.actor as any).isInstanceAdmin).toBe(false);
    expect(mockInsertValues).not.toHaveBeenCalled();
  });

  it("auto-promotes when only local-board admin exists", async () => {
    mockResolveSession.mockResolvedValue({
      user: { id: "user-1", email: "test@example.com", name: "Test" },
      session: { id: "sess-1", userId: "user-1" },
    });
    roleSelectResult = []; // user is NOT yet admin
    allAdminsResult = [{ userId: "local-board" }]; // only synthetic admin

    const middleware = actorMiddleware(mockDb as any, {
      deploymentMode: "authenticated",
      resolveSession: mockResolveSession,
    });
    const req = createRequest();
    const next = vi.fn();
    await middleware(req, {} as any, next);

    expect(next).toHaveBeenCalled();
    expect((req.actor as any).isInstanceAdmin).toBe(true);
    expect(mockInsertValues).toHaveBeenCalled();
  });

  it("skips auto-promote if user is already admin", async () => {
    mockResolveSession.mockResolvedValue({
      user: { id: "user-1", email: "test@example.com", name: "Test" },
      session: { id: "sess-1", userId: "user-1" },
    });
    roleSelectResult = [{ id: "role-1" }]; // user IS already admin

    const middleware = actorMiddleware(mockDb as any, {
      deploymentMode: "authenticated",
      resolveSession: mockResolveSession,
    });
    const req = createRequest();
    const next = vi.fn();
    await middleware(req, {} as any, next);

    expect(next).toHaveBeenCalled();
    expect((req.actor as any).isInstanceAdmin).toBe(true);
    // Should not even query for all admins since user already has the role
    expect(roleSelectCallCount).toBe(1);
  });

  it("recognises admin when BetterAuth hook promoted user before middleware check", async () => {
    // Race condition: BetterAuth hook already committed the admin role
    // between the initial roleSelect (stale, empty) and the allAdmins query.
    mockResolveSession.mockResolvedValue({
      user: { id: "user-1", email: "test@example.com", name: "Test" },
      session: { id: "sess-1", userId: "user-1" },
    });
    roleSelectResult = []; // initial check: user not yet admin (stale)
    allAdminsResult = [{ userId: "user-1" }]; // hook already promoted this user

    const middleware = actorMiddleware(mockDb as any, {
      deploymentMode: "authenticated",
      resolveSession: mockResolveSession,
    });
    const req = createRequest();
    const next = vi.fn();
    await middleware(req, {} as any, next);

    expect(next).toHaveBeenCalled();
    expect((req.actor as any).isInstanceAdmin).toBe(true);
    // Should NOT attempt insert — user already promoted by hook
    expect(mockInsertValues).not.toHaveBeenCalled();
  });

  it("re-checks admin after insert failure (unique constraint race)", async () => {
    // Race condition: insert fails because BetterAuth hook committed
    // concurrently. The catch block re-checks and finds the user is admin.
    mockResolveSession.mockResolvedValue({
      user: { id: "user-1", email: "test@example.com", name: "Test" },
      session: { id: "sess-1", userId: "user-1" },
    });
    roleSelectResult = []; // initial check: user not yet admin
    allAdminsResult = []; // no admins (race — hook hasn't committed yet)

    // Make insert throw (unique constraint violation)
    const recheckResult = [{ id: "role-1" }];
    const failingDb = createMockDb();
    failingDb.insert = vi.fn().mockReturnValue({
      values: vi.fn().mockReturnValue(Promise.reject(new Error("unique constraint"))),
    });
    // Override the third select call to return the re-check result
    let failingSelectCount = 0;
    failingDb.select = vi.fn().mockImplementation((fields?: Record<string, unknown>) => {
      const hasCompanyId = fields && "companyId" in fields;
      return {
        from: vi.fn().mockReturnValue({
          where: vi.fn().mockImplementation(() => {
            if (hasCompanyId) return Promise.resolve(membershipSelectResult);
            failingSelectCount++;
            if (failingSelectCount === 1) {
              // First: check if user has admin role
              return { then: (fn: (rows: unknown[]) => unknown) => Promise.resolve(fn(roleSelectResult)) };
            }
            if (failingSelectCount === 2) {
              // Second: list all admins for auto-promote
              return Promise.resolve(allAdminsResult);
            }
            // Third: re-check after insert failure
            return { then: (fn: (rows: unknown[]) => unknown) => Promise.resolve(fn(recheckResult)) };
          }),
        }),
      };
    });

    const middleware = actorMiddleware(failingDb as any, {
      deploymentMode: "authenticated",
      resolveSession: mockResolveSession,
    });
    const req = createRequest();
    const next = vi.fn();
    await middleware(req, {} as any, next);

    expect(next).toHaveBeenCalled();
    expect((req.actor as any).isInstanceAdmin).toBe(true);
  });
});
