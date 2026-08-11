import { describe, expect, it } from "vitest";
import { parseReportModel } from "../src/model";
import { sampleModel } from "./sample-model";

describe("versioned report model", () => {
  it("accepts the exact v1 shape", () => {
    const parsed = parseReportModel(structuredClone(sampleModel));
    expect(parsed.schemaVersion).toBe("tomorrowci.report/v1");
    expect(parsed.scenarios.map((scenario) => scenario.id)).toEqual([
      "baseline",
      "node22",
      "blocked-candidate",
    ]);
  });

  it("rejects unknown schemas instead of guessing", () => {
    const input = structuredClone(sampleModel) as unknown as Record<string, unknown>;
    input.schemaVersion = "tomorrowci.report/v2";
    expect(() => parseReportModel(input)).toThrow(/unsupported report model schema/);
  });

  it("rejects active or escaping evidence links", () => {
    const active = structuredClone(sampleModel);
    active.evidenceLinks[0].href = "javascript:alert(1)";
    expect(() => parseReportModel(active)).toThrow(/relative evidence link/);

    const traversal = structuredClone(sampleModel);
    traversal.evidenceLinks[0].href = "evidence/%2e%2e/secret";
    expect(() => parseReportModel(traversal)).toThrow(/unsafe path component/);
  });
});
