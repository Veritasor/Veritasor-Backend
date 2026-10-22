/**
 * Focused behavior coverage for `businessSchema`
 * (src/graphql/subgraphs/business.ts).
 *
 * `businessSchema` is a production GraphQL subgraph that had no dedicated test
 * fixture. These tests pin its public contract without booting Express or a
 * database:
 *
 * - the executable schema shape (query fields, argument types, field nullability)
 * - resolver delegation to the business repository (`getAll` / `getById`)
 * - the empty and not-found paths
 * - resolver rejection propagation
 * - repeated resolution issues a fresh repository call per request
 *
 * The repository module is mocked so the assertions describe the schema's own
 * behavior rather than the in-memory store's. Field/resolver access goes
 * through the schema object itself (`getQueryType().getFields()`), which keeps
 * this file independent of which `graphql` build the runtime resolved.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const { getAll, getById } = vi.hoisted(() => ({
  getAll: vi.fn(),
  getById: vi.fn(),
}));

vi.mock("../../../src/repositories/business.js", () => ({
  getAll,
  getById,
}));

import { businessSchema } from "../../../src/graphql/subgraphs/business.js";

function makeBusiness(overrides: Record<string, unknown> = {}) {
  return {
    id: "biz-1",
    userId: "user-1",
    name: "Acme Corporation",
    email: "ops@acme.test",
    industry: "Technology",
    description: "A leading technology company",
    website: "https://acme.test",
    reportingPeriod: "2026-05",
    reportingTimezone: "UTC",
    lastReminderSentAt: null,
    createdAt: "2026-05-01T00:00:00.000Z",
    updatedAt: "2026-05-02T00:00:00.000Z",
    ...overrides,
  };
}

type FieldMap = Record<
  string,
  {
    type: { toString(): string; name?: string };
    args: Array<{ name: string; type: { toString(): string } }>;
    resolve?: (...args: unknown[]) => unknown;
  }
>;

function queryFields(): FieldMap {
  const queryType = businessSchema.getQueryType();
  if (!queryType) throw new Error("businessSchema has no Query type");
  return queryType.getFields() as unknown as FieldMap;
}

function businessFields(): FieldMap {
  const businessType = businessSchema.getType("Business");
  if (!businessType) throw new Error("businessSchema has no Business type");
  return (businessType as unknown as { getFields(): FieldMap }).getFields();
}

/** Resolve a top-level query field the way the executor would. */
function resolveField(
  field: string,
  args: Record<string, unknown> = {},
): Promise<unknown> {
  const resolver = queryFields()[field]?.resolve;
  if (typeof resolver !== "function") {
    throw new Error(`Query.${field} has no resolver`);
  }
  return Promise.resolve(resolver({}, args, {}, {}));
}

describe("businessSchema — schema contract", () => {
  it("exposes exactly the businesses and business query fields", () => {
    expect(Object.keys(queryFields()).sort()).toEqual(["business", "businesses"]);
  });

  it("declares no mutation or subscription types", () => {
    expect(businessSchema.getMutationType()).toBeUndefined();
    expect(businessSchema.getSubscriptionType()).toBeUndefined();
  });

  it("types businesses as a non-null list of non-null Business", () => {
    expect(queryFields().businesses.type.toString()).toBe("[Business!]!");
  });

  it("types a single business lookup as a nullable Business", () => {
    expect(queryFields().business.type.toString()).toBe("Business");
  });

  it("requires a non-null ID argument for the business lookup", () => {
    const args = queryFields().business.args;
    expect(args.map((a) => `${a.name}: ${a.type.toString()}`)).toEqual(["id: ID!"]);
  });

  it("takes no arguments for the businesses list", () => {
    expect(queryFields().businesses.args).toEqual([]);
  });

  it("exposes the documented Business fields", () => {
    expect(Object.keys(businessFields())).toEqual([
      "id",
      "userId",
      "name",
      "email",
      "industry",
      "description",
      "website",
      "reportingPeriod",
      "reportingTimezone",
      "lastReminderSentAt",
      "createdAt",
      "updatedAt",
    ]);
  });

  it("marks required Business fields non-null and optional ones nullable", () => {
    const fields = businessFields();
    const nullability = Object.fromEntries(
      Object.entries(fields).map(([name, f]) => [name, f.type.toString()]),
    );

    expect(nullability).toMatchObject({
      id: "ID!",
      userId: "String!",
      name: "String!",
      email: "String!",
      reportingPeriod: "String!",
      reportingTimezone: "String!",
      createdAt: "String!",
      updatedAt: "String!",
      industry: "String",
      description: "String",
      website: "String",
      lastReminderSentAt: "String",
    });
  });
});

describe("businessSchema — businesses resolver", () => {
  beforeEach(() => {
    getAll.mockReset();
    getById.mockReset();
  });

  it("delegates to the repository and passes the result through", async () => {
    const rows = [makeBusiness(), makeBusiness({ id: "biz-2" })];
    getAll.mockResolvedValue(rows);

    const result = await resolveField("businesses");

    expect(getAll).toHaveBeenCalledTimes(1);
    expect(result).toBe(rows);
  });

  it("passes no filter arguments to the repository", async () => {
    getAll.mockResolvedValue([]);

    await resolveField("businesses");

    expect(getAll).toHaveBeenCalledWith();
  });

  it("returns an empty list when the repository has no businesses", async () => {
    getAll.mockResolvedValue([]);

    await expect(resolveField("businesses")).resolves.toEqual([]);
  });

  it("propagates a repository rejection instead of masking it", async () => {
    getAll.mockRejectedValue(new Error("database unavailable"));

    await expect(resolveField("businesses")).rejects.toThrow("database unavailable");
  });
});

describe("businessSchema — business(id) resolver", () => {
  beforeEach(() => {
    getAll.mockReset();
    getById.mockReset();
  });

  it("looks the business up by the supplied id", async () => {
    const row = makeBusiness({ id: "biz-42" });
    getById.mockResolvedValue(row);

    const result = await resolveField("business", { id: "biz-42" });

    expect(getById).toHaveBeenCalledTimes(1);
    expect(getById).toHaveBeenCalledWith("biz-42");
    expect(result).toBe(row);
  });

  it("returns null for an unknown id", async () => {
    getById.mockResolvedValue(null);

    await expect(resolveField("business", { id: "missing" })).resolves.toBeNull();
  });

  it("propagates a repository rejection", async () => {
    getById.mockRejectedValue(new Error("lookup failed"));

    await expect(resolveField("business", { id: "biz-1" })).rejects.toThrow(
      "lookup failed",
    );
  });

  it("issues a fresh repository call per resolution (no caching)", async () => {
    getById.mockResolvedValue(makeBusiness());

    await resolveField("business", { id: "biz-1" });
    await resolveField("business", { id: "biz-1" });

    expect(getById).toHaveBeenCalledTimes(2);
  });

  it("does not touch the list repository when resolving a single business", async () => {
    getById.mockResolvedValue(makeBusiness());

    await resolveField("business", { id: "biz-1" });

    expect(getAll).not.toHaveBeenCalled();
  });
});
