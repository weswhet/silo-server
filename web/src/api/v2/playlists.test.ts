import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  setAccessToken,
  setProfileId,
  setProfileToken,
  StaleApiRequestContextError,
} from "@/api/client";
import { resolvePlaylistEntry } from "./playlists";
const request = vi.hoisted(() => vi.fn());
vi.mock("./request", () => ({ v2: request }));
beforeEach(() => {
  request.mockReset();
  setAccessToken("account");
  setProfileId("profile");
  setProfileToken("proof");
});
describe("playlist resolver authority", () => {
  it("passes the captured owner to v2", async () => {
    request.mockResolvedValue({ entry: null });
    const result = await resolvePlaylistEntry("list", "entry");
    expect(request.mock.calls[0]![1].profileContext).toBe(result.authority);
    expect(result.authority.profileId).toBe("profile");
  });
  it.each(["pin", "account", "profile"])(
    "rejects a decoded result after %s authority changes",
    async (kind) => {
      let finish!: (value: unknown) => void;
      request.mockReturnValue(
        new Promise((resolve) => {
          finish = resolve;
        }),
      );
      const pending = resolvePlaylistEntry("list", "entry");
      if (kind === "pin") setProfileToken("proof");
      if (kind === "account") setAccessToken("new-account");
      if (kind === "profile") setProfileId("another-profile");
      finish({ entry: { item: { title: "Former title" } } });
      await expect(pending).rejects.toBeInstanceOf(StaleApiRequestContextError);
    },
  );
});
