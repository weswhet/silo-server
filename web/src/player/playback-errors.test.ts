import { describe, expect, it } from "vitest";
import { isUnavailablePlaybackFailure } from "./playback-errors";

describe("queue unavailable-item classification", () => {
  it.each([403, 404])("skips a definitive HTTP %s refusal", (status) => {
    expect(isUnavailablePlaybackFailure(status)).toBe(true);
  });
  it.each(["policy_denied", "source_unavailable", "source_unreadable"])(
    "skips %s terminal starts",
    (reason) => {
      expect(isUnavailablePlaybackFailure(undefined, reason)).toBe(true);
    },
  );
  it.each([401, 408, 429, 500, 503, undefined])(
    "does not treat HTTP %s as an unavailable title",
    (status) => {
      expect(isUnavailablePlaybackFailure(status)).toBe(false);
    },
  );
  it("does not skip when the deployment cannot currently transcode", () => {
    expect(isUnavailablePlaybackFailure(undefined, "transcode_node_unavailable")).toBe(false);
  });
});
