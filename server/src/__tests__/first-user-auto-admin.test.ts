import { describe, expect, it, vi, beforeEach } from "vitest";

/**
 * Tests for the first-user auto-admin databaseHooks logic
 * in createBetterAuthInstance.
 *
 * We extract the hook callback by mocking betterAuth and capturing
 * the config passed to it.
 */

// Capture the config passed to betterAuth
let capturedConfig: Record<string, unknown> | null = null;

vi.mock("better-auth", () => ({
  betterAuth: (config: Record<string, unknown>) => {
    capturedConfig = config;
    return {} as ReturnType<typeof import("better-auth").betterAuth>;
  },
}));

vi.mock("better-auth/adapters/drizzle", () => ({
  drizzleAdapter: () => ({}),
}));

vi.mock("better-auth/node", () => ({
  toNodeHandler: () => () => {},
}));

// Mock DB
const mockSelect = vi.fn();
const mockFrom = vi.fn();
const mockLimit = vi.fn();
const mockInsert = vi.fn();
const mockValues = vi.fn();

const mockDb = {
  select: mockSelect,
  insert: mockInsert,
} as unknown as import("@paperclipai/db").Db;

const mockConfig = {
  authBaseUrlMode: "auto" as const,
  authPublicBaseUrl: "",
  deploymentMode: "authenticated" as const,
  allowedHostnames: [],
  authDisableSignUp: false,
} as unknown as import("../config.js").Config;

beforeEach(() => {
  vi.clearAllMocks();
  capturedConfig = null;

  // Chain: db.select(...).from(...).limit(...)
  mockSelect.mockReturnValue({ from: mockFrom });
  mockFrom.mockReturnValue({ limit: mockLimit });

  // Chain: db.insert(...).values(...)
  mockInsert.mockReturnValue({ values: mockValues });
  mockValues.mockResolvedValue(undefined);
});

describe("first-user auto-admin hook", () => {
  it("grants instance_admin to first user when no admins exist", async () => {
    // No existing admins
    mockLimit.mockResolvedValue([]);

    const { createBetterAuthInstance } = await import("../auth/better-auth.js");
    createBetterAuthInstance(mockDb, mockConfig);

    const hooks = capturedConfig?.databaseHooks as {
      user: { create: { after: (user: { id: string }) => Promise<void> } };
    };
    expect(hooks?.user?.create?.after).toBeDefined();

    await hooks.user.create.after({ id: "user-1" });

    expect(mockSelect).toHaveBeenCalled();
    expect(mockInsert).toHaveBeenCalled();
    expect(mockValues).toHaveBeenCalledWith({
      userId: "user-1",
      role: "instance_admin",
    });
  });

  it("does NOT grant admin when admins already exist", async () => {
    // Existing admin found
    mockLimit.mockResolvedValue([{ id: "existing-admin-role" }]);

    const { createBetterAuthInstance } = await import("../auth/better-auth.js");
    createBetterAuthInstance(mockDb, mockConfig);

    const hooks = capturedConfig?.databaseHooks as {
      user: { create: { after: (user: { id: string }) => Promise<void> } };
    };

    await hooks.user.create.after({ id: "user-2" });

    expect(mockSelect).toHaveBeenCalled();
    expect(mockInsert).not.toHaveBeenCalled();
  });
});
