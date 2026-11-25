vi.mock("@/hooks/queries/playlists", () => ({ usePlaylistAuthorityKey: () => "owner" }));
import { act, render, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createWatchRouteRequest } from "./watchRouteHelpers";
import WatchRoute from "./WatchRoute";

const calls = vi.hoisted(() => ({
  sync: vi.fn(),
  exit: vi.fn(),
  stop: vi.fn(),
  start: vi.fn(),
  resolve: vi.fn(),
  current: vi.fn(),
}));
vi.mock("@/api/client", () => ({
  captureProfileRequestContext: () => ({}),
  isCapturedProfileAuthorityActive: calls.current,
}));
vi.mock("@/api/v2/playlists", () => ({
  isPlaylistAuthorityCurrent: calls.current,
  resolvePlaylistEntry: calls.resolve,
}));
vi.mock("@/playback/watchPlaybackContext", async () => ({
  WatchPlaybackControllerContext: (await import("react")).createContext({
    syncRouteRequest: calls.sync,
    handleRouteExit: calls.exit,
    stopPlayback: calls.stop,
    startPlayback: calls.start,
  }),
}));
function mount(search = "?playlist=playlist&entry=duplicate-2&restart=1") {
  return render(
    <MemoryRouter
      initialEntries={[
        {
          pathname: "/watch/movie",
          search,
          state: { watchReturnHref: "/playlists/playlist", versionPicked: true },
        },
      ]}
    >
      <Routes>
        <Route path="/watch/:id" element={<WatchRoute />} />
        <Route path="/playlists/:id" element={<div>Playlist</div>} />
      </Routes>
    </MemoryRouter>,
  );
}
beforeEach(() => {
  vi.clearAllMocks();
  calls.current.mockReturnValue(true);
  calls.resolve.mockResolvedValue({ entry: { id: "duplicate-2", item_id: "movie" } });
});
describe("watch route controller", () => {
  it("resolves the owner and cursor before adopting a refreshed URL, preserving multipart selection", async () => {
    let finish!: (value: unknown) => void;
    calls.resolve.mockReturnValue(
      new Promise((resolve) => {
        finish = resolve;
      }),
    );
    mount("?playlist=playlist&entry=duplicate-2&restart=1&fileId=42");
    expect(calls.sync).not.toHaveBeenCalled();
    await act(async () => finish({ entry: { id: "duplicate-2", item_id: "movie" } }));
    expect(calls.resolve).toHaveBeenCalledWith("playlist", "duplicate-2");
    expect(calls.sync).toHaveBeenCalledWith(
      createWatchRouteRequest({
        contentId: "movie",
        playlistId: "playlist",
        playlistEntryId: "duplicate-2",
        restart: true,
        fileId: 42,
        versionPicked: true,
        returnHref: "/playlists/playlist",
      }),
    );
  });
  it.each([null, "denied"])(
    "does not adopt URL content when resolution returns %s",
    async (result) => {
      if (result) calls.resolve.mockRejectedValue(new Error("denied"));
      else calls.resolve.mockResolvedValue({ entry: null });
      mount();
      await waitFor(() => expect(calls.stop).toHaveBeenCalled());
      expect(calls.sync).not.toHaveBeenCalled();
      expect(calls.start).not.toHaveBeenCalled();
    },
  );
  it("replaces stale URL content with the resolved entry without inheriting its file", async () => {
    calls.resolve.mockResolvedValue({ entry: { id: "next", item_id: "episode" } });
    mount("?playlist=playlist&entry=duplicate-2&fileId=42");
    await waitFor(() =>
      expect(calls.start).toHaveBeenCalledWith(
        {
          contentId: "episode",
          playlistId: "playlist",
          playlistEntryId: "next",
          restart: true,
          returnHref: "/playlists/playlist",
        },
        "automatic",
      ),
    );
    expect(calls.sync).not.toHaveBeenCalled();
  });
  it.each(["unmount", "authority"])(
    "ignores a late resolution after %s changes",
    async (change) => {
      let finish!: (value: unknown) => void;
      calls.resolve.mockReturnValue(
        new Promise((resolve) => {
          finish = resolve;
        }),
      );
      const view = mount();
      if (change === "unmount") view.unmount();
      else calls.current.mockReturnValue(false);
      await act(async () => finish({ entry: { id: "duplicate-2", item_id: "movie" } }));
      expect(calls.sync).not.toHaveBeenCalled();
      expect(calls.start).not.toHaveBeenCalled();
    },
  );
});
