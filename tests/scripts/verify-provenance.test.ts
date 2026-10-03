/**
 * Tests for scripts/verify-provenance.ts (issue #565).
 * Covers DSSE envelope parsing, in-toto statement validation, digest binding,
 * builder / source-repo identity checks, CLI parsing, and the CLI driver —
 * including the "provenance verification failure" edge cases.
 */

import { describe, it, expect, vi } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  parseDsseEnvelope,
  decodeStatement,
  sha256Hex,
  findMatchingSubject,
  verifyBuilderIdentity,
  verifyProvenance,
  parseCliArgs,
  runVerifyProvenanceCli,
  handleVerifyProvenanceCliFailure,
  isVerifyProvenanceCliEntrypoint,
  ProvenanceVerificationError,
  EXPECTED_BUILDER_ID_PREFIX,
  SLSA_V1_PREDICATE_TYPE,
  DSSE_PAYLOAD_TYPE,
  type InTotoStatement,
} from "../../scripts/verify-provenance";

// ─── fixtures ────────────────────────────────────────────────────────────────

const ARTIFACT_CONTENT = "release artifact bytes";
const ARTIFACT_SHA256 = sha256Hex(ARTIFACT_CONTENT);
const BUILDER_ID = `${EXPECTED_BUILDER_ID_PREFIX}v2.1.0`;
const SOURCE_REPO = "https://github.com/aburex12345/Veritasor-Backend";

function makeStatement(overrides: Partial<InTotoStatement> = {}): InTotoStatement {
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "veritasor-backend-v1.0.0.tgz", digest: { sha256: ARTIFACT_SHA256 } }],
    predicateType: SLSA_V1_PREDICATE_TYPE,
    predicate: {
      buildDefinition: { externalParameters: { workflow: { repository: SOURCE_REPO } } },
      runDetails: { builder: { id: BUILDER_ID } },
    },
    ...overrides,
  };
}

function makeEnvelopeRaw(
  statement: unknown = makeStatement(),
  envelopeOverrides: Record<string, unknown> = {}
): string {
  return JSON.stringify({
    payload: Buffer.from(JSON.stringify(statement)).toString("base64"),
    payloadType: DSSE_PAYLOAD_TYPE,
    signatures: [{ sig: "MEUCIQDsig==", keyid: "" }],
    ...envelopeOverrides,
  });
}

// ─── parseDsseEnvelope ───────────────────────────────────────────────────────

describe("parseDsseEnvelope", () => {
  it("parses a valid single-line DSSE envelope", () => {
    const env = parseDsseEnvelope(makeEnvelopeRaw());
    expect(env.payloadType).toBe(DSSE_PAYLOAD_TYPE);
    expect(env.signatures).toHaveLength(1);
  });

  it("skips leading blank lines in .jsonl files", () => {
    const env = parseDsseEnvelope(`\n\n${makeEnvelopeRaw()}\n`);
    expect(env.payloadType).toBe(DSSE_PAYLOAD_TYPE);
  });

  it("rejects an empty file", () => {
    expect(() => parseDsseEnvelope("")).toThrowError(ProvenanceVerificationError);
    expect(() => parseDsseEnvelope("  \n ")).toThrow(/empty/i);
  });

  it("rejects non-JSON content", () => {
    try {
      parseDsseEnvelope("not-json{");
      expect.unreachable();
    } catch (err) {
      expect((err as ProvenanceVerificationError).code).toBe("MALFORMED_ENVELOPE");
    }
  });

  it("rejects envelopes missing payload or payloadType", () => {
    expect(() => parseDsseEnvelope(JSON.stringify({ payloadType: DSSE_PAYLOAD_TYPE })))
      .toThrow(/payload/);
    expect(() => parseDsseEnvelope(JSON.stringify({ payload: "abc" })))
      .toThrow(/payloadType/);
    expect(() => parseDsseEnvelope("null")).toThrow(/payload/);
  });

  it("rejects unexpected payloadType", () => {
    try {
      parseDsseEnvelope(makeEnvelopeRaw(makeStatement(), { payloadType: "application/json" }));
      expect.unreachable();
    } catch (err) {
      expect((err as ProvenanceVerificationError).code).toBe("BAD_PAYLOAD_TYPE");
    }
  });

  it("rejects unsigned envelopes (missing, empty, or blank signatures)", () => {
    for (const signatures of [undefined, [], [{ sig: "" }]]) {
      try {
        parseDsseEnvelope(makeEnvelopeRaw(makeStatement(), { signatures }));
        expect.unreachable();
      } catch (err) {
        expect((err as ProvenanceVerificationError).code).toBe("UNSIGNED_ENVELOPE");
      }
    }
  });
});

// ─── decodeStatement ─────────────────────────────────────────────────────────

describe("decodeStatement", () => {
  it("decodes a valid SLSA v1 statement", () => {
    const stmt = decodeStatement(parseDsseEnvelope(makeEnvelopeRaw()));
    expect(stmt.predicateType).toBe(SLSA_V1_PREDICATE_TYPE);
    expect(stmt.subject).toHaveLength(1);
  });

  it("accepts the legacy v0.1 statement _type", () => {
    const stmt = decodeStatement(
      parseDsseEnvelope(
        makeEnvelopeRaw(makeStatement({ _type: "https://in-toto.io/Statement/v0.1" }))
      )
    );
    expect(stmt._type).toBe("https://in-toto.io/Statement/v0.1");
  });

  it("rejects payloads that are not base64 JSON", () => {
    try {
      decodeStatement({
        payload: "!!!not-base64-json!!!",
        payloadType: DSSE_PAYLOAD_TYPE,
        signatures: [{ sig: "x" }],
      });
      expect.unreachable();
    } catch (err) {
      expect((err as ProvenanceVerificationError).code).toBe("MALFORMED_STATEMENT");
    }
  });

  it("rejects payloads that are not statements", () => {
    for (const payload of [null, 42, { subject: [] }]) {
      try {
        decodeStatement(parseDsseEnvelope(makeEnvelopeRaw(payload)));
        expect.unreachable();
      } catch (err) {
        expect((err as ProvenanceVerificationError).code).toBe("MALFORMED_STATEMENT");
      }
    }
  });

  it("rejects unknown statement _type", () => {
    try {
      decodeStatement(
        parseDsseEnvelope(makeEnvelopeRaw(makeStatement({ _type: "https://evil.example/v9" })))
      );
      expect.unreachable();
    } catch (err) {
      expect((err as ProvenanceVerificationError).code).toBe("BAD_STATEMENT_TYPE");
    }
  });

  it("rejects non-SLSA-v1 predicate types (e.g. SLSA v0.2)", () => {
    try {
      decodeStatement(
        parseDsseEnvelope(
          makeEnvelopeRaw(makeStatement({ predicateType: "https://slsa.dev/provenance/v0.2" }))
        )
      );
      expect.unreachable();
    } catch (err) {
      expect((err as ProvenanceVerificationError).code).toBe("BAD_PREDICATE_TYPE");
    }
  });

  it("rejects statements without subjects", () => {
    for (const subject of [[], undefined]) {
      try {
        decodeStatement(
          parseDsseEnvelope(makeEnvelopeRaw(makeStatement({ subject: subject as never })))
        );
        expect.unreachable();
      } catch (err) {
        expect((err as ProvenanceVerificationError).code).toBe("NO_SUBJECTS");
      }
    }
  });
});

// ─── sha256Hex ───────────────────────────────────────────────────────────────

describe("sha256Hex", () => {
  it("computes the well-known digest of an empty string", () => {
    expect(sha256Hex("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
  });

  it("accepts buffers and strings equally", () => {
    expect(sha256Hex(Buffer.from("abc"))).toBe(sha256Hex("abc"));
  });
});

// ─── findMatchingSubject ─────────────────────────────────────────────────────

describe("findMatchingSubject", () => {
  it("finds the subject by digest", () => {
    const subject = findMatchingSubject(makeStatement(), ARTIFACT_SHA256);
    expect(subject.name).toBe("veritasor-backend-v1.0.0.tgz");
  });

  it("matches digests case-insensitively", () => {
    const subject = findMatchingSubject(makeStatement(), ARTIFACT_SHA256.toUpperCase());
    expect(subject.digest.sha256).toBe(ARTIFACT_SHA256);
  });

  it("fails when no subject carries the artifact digest (tampered artifact)", () => {
    try {
      findMatchingSubject(makeStatement(), sha256Hex("tampered bytes"));
      expect.unreachable();
    } catch (err) {
      const e = err as ProvenanceVerificationError;
      expect(e.code).toBe("SUBJECT_DIGEST_MISMATCH");
      expect(e.message).toContain("veritasor-backend-v1.0.0.tgz");
    }
  });

  it("selects the right subject among several by name", () => {
    const stmt = makeStatement({
      subject: [
        { name: "other.tgz", digest: { sha256: sha256Hex("other") } },
        { name: "veritasor-backend-v1.0.0.tgz", digest: { sha256: ARTIFACT_SHA256 } },
      ],
    });
    const subject = findMatchingSubject(stmt, ARTIFACT_SHA256, "veritasor-backend-v1.0.0.tgz");
    expect(subject.name).toBe("veritasor-backend-v1.0.0.tgz");
  });

  it("compares subject names by basename (paths tolerated)", () => {
    const subject = findMatchingSubject(
      makeStatement(),
      ARTIFACT_SHA256,
      "/tmp/download/veritasor-backend-v1.0.0.tgz"
    );
    expect(subject.name).toBe("veritasor-backend-v1.0.0.tgz");
  });

  it("fails when the digest matches but the name does not", () => {
    try {
      findMatchingSubject(makeStatement(), ARTIFACT_SHA256, "unexpected-name.tgz");
      expect.unreachable();
    } catch (err) {
      expect((err as ProvenanceVerificationError).code).toBe("SUBJECT_DIGEST_MISMATCH");
    }
  });

  it("tolerates subjects with missing digests when another subject matches", () => {
    const stmt = makeStatement({
      subject: [
        { name: "no-digest.tgz", digest: {} as never },
        { name: "veritasor-backend-v1.0.0.tgz", digest: { sha256: ARTIFACT_SHA256 } },
      ],
    });
    expect(findMatchingSubject(stmt, ARTIFACT_SHA256).name).toBe(
      "veritasor-backend-v1.0.0.tgz"
    );
  });
});

// ─── verifyBuilderIdentity ───────────────────────────────────────────────────

describe("verifyBuilderIdentity", () => {
  it("accepts the trusted slsa-github-generator builder", () => {
    const { builderId, sourceRepo } = verifyBuilderIdentity(makeStatement());
    expect(builderId).toBe(BUILDER_ID);
    expect(sourceRepo).toBe(SOURCE_REPO);
  });

  it("rejects untrusted builders", () => {
    const stmt = makeStatement({
      predicate: {
        ...makeStatement().predicate,
        runDetails: { builder: { id: "https://github.com/evil/builder@refs/tags/v1" } },
      },
    });
    try {
      verifyBuilderIdentity(stmt);
      expect.unreachable();
    } catch (err) {
      expect((err as ProvenanceVerificationError).code).toBe("BUILDER_MISMATCH");
    }
  });

  it("rejects statements missing the builder id entirely", () => {
    const stmt = makeStatement({ predicate: {} });
    expect(() => verifyBuilderIdentity(stmt)).toThrow(/Untrusted builder/);
  });

  it("honours a custom builder prefix", () => {
    const stmt = makeStatement({
      predicate: {
        ...makeStatement().predicate,
        runDetails: { builder: { id: "https://example.com/custom-builder@refs/tags/v1" } },
      },
    });
    const { builderId } = verifyBuilderIdentity(stmt, "https://example.com/custom-builder@");
    expect(builderId).toContain("custom-builder");
  });

  it("normalizes source repo forms (scheme, .git, trailing slash, case)", () => {
    for (const expected of [
      "github.com/aburex12345/Veritasor-Backend",
      "https://github.com/aburex12345/veritasor-backend/",
      "github.com/aburex12345/Veritasor-Backend.git",
    ]) {
      const { sourceRepo } = verifyBuilderIdentity(
        makeStatement(),
        EXPECTED_BUILDER_ID_PREFIX,
        expected
      );
      expect(sourceRepo).toBe(SOURCE_REPO);
    }
  });

  it("rejects a provenance built from a different repository", () => {
    try {
      verifyBuilderIdentity(
        makeStatement(),
        EXPECTED_BUILDER_ID_PREFIX,
        "github.com/someone-else/Other-Repo"
      );
      expect.unreachable();
    } catch (err) {
      expect((err as ProvenanceVerificationError).code).toBe("SOURCE_REPO_MISMATCH");
    }
  });

  it("rejects when expected source repo is set but provenance has none", () => {
    const stmt = makeStatement({
      predicate: { runDetails: { builder: { id: BUILDER_ID } } },
    });
    expect(() =>
      verifyBuilderIdentity(stmt, EXPECTED_BUILDER_ID_PREFIX, "github.com/a/b")
    ).toThrow(/does not match/);
  });

  it("skips the source check when no expected repo is provided", () => {
    const stmt = makeStatement({
      predicate: { runDetails: { builder: { id: BUILDER_ID } } },
    });
    expect(verifyBuilderIdentity(stmt).sourceRepo).toBeUndefined();
  });
});

// ─── verifyProvenance (end to end) ───────────────────────────────────────────

describe("verifyProvenance", () => {
  it("verifies a valid artifact + provenance pair", () => {
    const report = verifyProvenance({
      provenanceRaw: makeEnvelopeRaw(),
      artifactSha256: ARTIFACT_SHA256,
      artifactName: "veritasor-backend-v1.0.0.tgz",
      expectedSourceRepo: "github.com/aburex12345/Veritasor-Backend",
    });
    expect(report).toEqual({
      subjectName: "veritasor-backend-v1.0.0.tgz",
      sha256: ARTIFACT_SHA256,
      builderId: BUILDER_ID,
      sourceRepo: SOURCE_REPO,
      predicateType: SLSA_V1_PREDICATE_TYPE,
    });
  });

  it("fails end-to-end on digest mismatch (verification failure edge case)", () => {
    expect(() =>
      verifyProvenance({
        provenanceRaw: makeEnvelopeRaw(),
        artifactSha256: sha256Hex("attacker-modified"),
      })
    ).toThrow(ProvenanceVerificationError);
  });
});

// ─── CLI ─────────────────────────────────────────────────────────────────────

describe("parseCliArgs", () => {
  it("parses all supported flags", () => {
    expect(
      parseCliArgs([
        "--provenance", "p.intoto.jsonl",
        "--artifact", "a.tgz",
        "--source-repo", "github.com/o/r",
        "--builder-id-prefix", "https://x/",
      ])
    ).toEqual({
      provenance: "p.intoto.jsonl",
      artifact: "a.tgz",
      sourceRepo: "github.com/o/r",
      builderIdPrefix: "https://x/",
    });
  });

  it("requires --provenance and --artifact", () => {
    expect(() => parseCliArgs([])).toThrow(/Usage/);
    expect(() => parseCliArgs(["--provenance", "p"])).toThrow(/Usage/);
    expect(() => parseCliArgs(["--artifact", "a"])).toThrow(/Usage/);
  });

  it("rejects unknown flags", () => {
    expect(() => parseCliArgs(["--nope", "x"])).toThrow(/Unknown argument: --nope/);
  });
});

describe("runVerifyProvenanceCli", () => {
  async function writeFixtures(provenanceRaw: string): Promise<{ prov: string; art: string }> {
    const dir = await mkdtemp(join(tmpdir(), "slsa-test-"));
    const prov = join(dir, "veritasor-backend-v1.0.0.intoto.jsonl");
    const art = join(dir, "veritasor-backend-v1.0.0.tgz");
    await writeFile(prov, provenanceRaw);
    await writeFile(art, ARTIFACT_CONTENT);
    return { prov, art };
  }

  it("verifies real files and prints PASS", async () => {
    const { prov, art } = await writeFixtures(makeEnvelopeRaw());
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const report = await runVerifyProvenanceCli([
      "--provenance", prov,
      "--artifact", art,
      "--source-repo", "github.com/aburex12345/Veritasor-Backend",
    ]);

    expect(report.sha256).toBe(ARTIFACT_SHA256);
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining("PASS"));
    logSpy.mockRestore();
  });

  it("rejects when the artifact does not match the provenance", async () => {
    const tamperedStatement = makeStatement({
      subject: [{ name: "veritasor-backend-v1.0.0.tgz", digest: { sha256: sha256Hex("x") } }],
    });
    const { prov, art } = await writeFixtures(makeEnvelopeRaw(tamperedStatement));

    await expect(
      runVerifyProvenanceCli(["--provenance", prov, "--artifact", art])
    ).rejects.toThrow(ProvenanceVerificationError);
  });

  it("propagates fs errors for missing files", async () => {
    await expect(
      runVerifyProvenanceCli([
        "--provenance", "/nonexistent/p.intoto.jsonl",
        "--artifact", "/nonexistent/a.tgz",
      ])
    ).rejects.toThrow();
  });
});

describe("handleVerifyProvenanceCliFailure", () => {
  it("prints the failure code for verification errors and exits 1", () => {
    const exitFn = vi.fn(() => {
      throw new Error("exited");
    }) as unknown as (code: number) => never;
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(() =>
      handleVerifyProvenanceCliFailure(
        new ProvenanceVerificationError("SUBJECT_DIGEST_MISMATCH", "digest mismatch"),
        exitFn
      )
    ).toThrow("exited");
    expect(errSpy).toHaveBeenCalledWith("FAIL [SUBJECT_DIGEST_MISMATCH]: digest mismatch");
    expect(exitFn).toHaveBeenCalledWith(1);
    errSpy.mockRestore();
  });

  it("handles generic errors and non-Error values", () => {
    const exitFn = vi.fn(() => {
      throw new Error("exited");
    }) as unknown as (code: number) => never;
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(() => handleVerifyProvenanceCliFailure(new Error("io error"), exitFn)).toThrow("exited");
    expect(errSpy).toHaveBeenCalledWith("FAIL: io error");

    expect(() => handleVerifyProvenanceCliFailure("string failure", exitFn)).toThrow("exited");
    expect(errSpy).toHaveBeenCalledWith("FAIL: string failure");
    errSpy.mockRestore();
  });
});

describe("isVerifyProvenanceCliEntrypoint", () => {
  it("is true only when argv[1] equals the module path", () => {
    const moduleUrl = import.meta.url;
    const selfPath = fileURLToPath(moduleUrl);
    expect(isVerifyProvenanceCliEntrypoint(selfPath, moduleUrl)).toBe(true);
    expect(isVerifyProvenanceCliEntrypoint("/other", moduleUrl)).toBe(false);
    expect(isVerifyProvenanceCliEntrypoint(undefined, moduleUrl)).toBe(false);
  });
});
