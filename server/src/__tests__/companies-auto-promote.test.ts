import express from "express";
import request from "supertest";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { companyRoutes } from "../routes/companies.js";

const mockCreate = vi.fn().mockResolvedValue({ id: "co-1", name: "Test Co", issuePrefix: "TC" });
const mockEnsureMembership = vi.fn().mockResolvedValue({});
const mockAutoPromoteFirstAdmin = vi.fn();

vi.mock("../services/index.js", () => ({
  companyService: () => ({
    list: vi.fn(),
    stats: vi.fn(),
    getById: vi.fn(),
    create: mockCreate,
    update: vi.fn(),
    archive: vi.fn(),
    remove: vi.fn(),
  }),
  companyPortabilityService: () => ({
    exportBundle: vi.fn(),
    previewImport: vi.fn(),
    importBundle: vi.fn(),
  }),
  accessService: () => ({
    canUser: vi.fn(),
    ensureMembership: mockEnsureMembership,
    autoPromoteFirstAdmin: mockAutoPromoteFirstAdmin,
  }),
  logActivity: vi.fn(),
}));

function buildApp(actor: Record<string, unknown>) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    (req as any).actor = actor;
    next();
  });
  app.use("/api/companies", companyRoutes({} as any));
  // Error handler to catch thrown errors
  app.use((err: any, _req: any, res: any, _next: any) => {
    res.status(err.status ?? err.statusCode ?? 500).json({ error: err.message });
  });
  return app;
}

describe("POST /api/companies — first-user auto-promotion", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("auto-promotes the first user when no admins exist", async () => {
    mockAutoPromoteFirstAdmin.mockResolvedValue(true);
    const app = buildApp({
      type: "board",
      userId: "user-1",
      companyIds: [],
      isInstanceAdmin: false,
      source: "session",
    });

    const res = await request(app)
      .post("/api/companies")
      .send({ name: "My Company" });

    expect(res.status).toBe(201);
    expect(mockAutoPromoteFirstAdmin).toHaveBeenCalledWith("user-1");
    expect(mockCreate).toHaveBeenCalled();
  });

  it("rejects non-admin user when admins already exist", async () => {
    mockAutoPromoteFirstAdmin.mockResolvedValue(false);
    const app = buildApp({
      type: "board",
      userId: "user-2",
      companyIds: [],
      isInstanceAdmin: false,
      source: "session",
    });

    const res = await request(app)
      .post("/api/companies")
      .send({ name: "Forbidden Co" });

    expect(res.status).toBe(403);
    expect(mockCreate).not.toHaveBeenCalled();
  });

  it("skips auto-promote for instance admins", async () => {
    const app = buildApp({
      type: "board",
      userId: "admin-1",
      companyIds: [],
      isInstanceAdmin: true,
      source: "session",
    });

    const res = await request(app)
      .post("/api/companies")
      .send({ name: "Admin Co" });

    expect(res.status).toBe(201);
    expect(mockAutoPromoteFirstAdmin).not.toHaveBeenCalled();
  });

  it("skips auto-promote for local_implicit mode", async () => {
    const app = buildApp({
      type: "board",
      userId: "local-board",
      companyIds: [],
      isInstanceAdmin: false,
      source: "local_implicit",
    });

    const res = await request(app)
      .post("/api/companies")
      .send({ name: "Local Co" });

    expect(res.status).toBe(201);
    expect(mockAutoPromoteFirstAdmin).not.toHaveBeenCalled();
  });
});
