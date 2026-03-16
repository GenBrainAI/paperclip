import { describe, expect, it, vi, beforeEach } from "vitest";

/**
 * Tests that autoPromoteFirstAdmin correctly ignores the synthetic
 * "local-board" user when deciding whether real admins exist.
 *
 * Bug: When Paperclip runs in authenticated mode, the server creates
 * a "local-board" user with instance_admin at startup. The old code
 * checked for ANY instance_admin rows, found local-board, and refused
 * to promote the first real user — blocking onboarding.
 */

let selectCallCount = 0;
let mockAdminRows: Array<{ id: string; userId: string }> = [];
const mockInsertValues = vi.fn();

const mockDb = {
  select: vi.fn().mockImplementation(() => {
    selectCallCount++;
    const currentCall = selectCallCount;
    return {
      from: vi.fn().mockReturnValue({
        where: vi.fn().mockImplementation(() => ({
          limit: vi.fn().mockImplementation(() =>
            // First select: list all admins; second select: check if user already has role
            Promise.resolve(currentCall === 1 ? mockAdminRows : []),
          ),
          then: (fn: (rows: unknown[]) => unknown) =>
            // First select: list all admins; second select: check if user already has role
            Promise.resolve(fn(currentCall === 1 ? mockAdminRows : [])),
        })),
      }),
    };
  }),
  insert: vi.fn().mockReturnValue({
    values: mockInsertValues.mockReturnValue({
      returning: vi.fn().mockReturnValue({
        then: (fn: (rows: unknown[]) => unknown) =>
          Promise.resolve(fn([{ id: "new-role", userId: "real-user", role: "instance_admin" }])),
      }),
    }),
  }),
};

vi.mock("@paperclipai/db", () => ({
  instanceUserRoles: { id: "id", userId: "userId", role: "role" },
  companyMemberships: {},
  principalPermissionGrants: {},
}));

vi.mock("drizzle-orm", () => ({
  eq: vi.fn((_col: unknown, val: unknown) => val),
  and: vi.fn((...args: unknown[]) => args),
  inArray: vi.fn(),
  sql: vi.fn(),
}));

const { accessService } = await import("../services/access.js");

describe("autoPromoteFirstAdmin — local-board exclusion", () => {
  let access: ReturnType<typeof accessService>;

  beforeEach(() => {
    vi.clearAllMocks();
    selectCallCount = 0;
    access = accessService(mockDb as any);
  });

  it("promotes user when only local-board has instance_admin", async () => {
    mockAdminRows = [{ id: "role-1", userId: "local-board" }];
    const promoted = await access.autoPromoteFirstAdmin("real-user");
    expect(promoted).toBe(true);
    expect(mockInsertValues).toHaveBeenCalled();
  });

  it("does NOT promote when a real admin already exists", async () => {
    mockAdminRows = [
      { id: "role-1", userId: "local-board" },
      { id: "role-2", userId: "existing-admin" },
    ];
    const promoted = await access.autoPromoteFirstAdmin("new-user");
    expect(promoted).toBe(false);
    expect(mockInsertValues).not.toHaveBeenCalled();
  });

  it("promotes user when instance_user_roles is completely empty", async () => {
    mockAdminRows = [];
    const promoted = await access.autoPromoteFirstAdmin("first-user");
    expect(promoted).toBe(true);
    expect(mockInsertValues).toHaveBeenCalled();
  });
});
