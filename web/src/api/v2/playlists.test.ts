import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  setAccessToken,
  setProfileId,
  setProfileToken,
  StaleApiRequestContextError,
} from "@/api/client";
import { QueryClient } from "@tanstack/react-query";
import { resolvePlaylistEntry, getPlaylist, capturePlaylistAuthority } from "./playlists";
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
    expect(request.mock.calls[0]![1].profileContext).toMatchObject(result.authority);
    expect(Object.keys(result.authority).sort()).toEqual([
      "authContextVersion",
      "profileId",
      "profileTokenGeneration",
      "serverOrigin",
    ]);
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

it("retains no bearer or PIN proof in query data, mutation results, or mutation variables", async () => {
  request.mockImplementation(async (_operation, options) => {
    options.onResponse?.(new Response(null, { headers: { ETag: '"1"' } }));
    return { entry: null };
  });
  const client = new QueryClient();
  await client.fetchQuery({ queryKey: ["detail"], queryFn: () => getPlaylist("list") });
  await client.fetchQuery({
    queryKey: ["next"],
    queryFn: () => resolvePlaylistEntry("list", "entry"),
  });
  const mutation = client.getMutationCache().build(client, {
    mutationFn: async (_variables: { authority: ReturnType<typeof capturePlaylistAuthority> }) =>
      resolvePlaylistEntry("list", "entry"),
  });
  await mutation.execute({ authority: capturePlaylistAuthority() });
  const retained = [
    ...client
      .getQueryCache()
      .getAll()
      .map((query) => query.state.data),
    ...client
      .getMutationCache()
      .getAll()
      .flatMap((item) => [item.state.data, item.state.variables]),
  ];
  function check(value: unknown) {
    if (!value || typeof value !== "object") return;
    expect(value).not.toHaveProperty("accessToken");
    expect(value).not.toHaveProperty("profileToken");
    for (const child of Object.values(value)) check(child);
  }
  retained.forEach(check);
  expect(JSON.stringify(retained)).not.toContain('"account"');
  expect(JSON.stringify(retained)).not.toContain('"proof"');
  client.clear();
});
