import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const packageJson = JSON.parse(
  readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
) as {
  engines?: { node?: string };
  packageManager?: string;
};

describe("package runtime metadata", () => {
  it("requires Node.js 22 or newer", () => {
    expect(packageJson.engines?.node).toBe(">=22");
  });

  it("pins pnpm 10 through Corepack", () => {
    expect(packageJson.packageManager).toBe("pnpm@10.x");
  });

  it("provides Node 22 for nvm", () => {
    const nvmrc = readFileSync(new URL("../../.nvmrc", import.meta.url), "utf8").trim();
    expect(nvmrc).toBe("22");
  });

  it("documents the Node and pnpm prerequisites", () => {
    const readme = readFileSync(new URL("../../README.md", import.meta.url), "utf8");
    expect(readme).toContain("Node.js 22 or newer");
    expect(readme).toContain("pnpm 10");
  });
});
