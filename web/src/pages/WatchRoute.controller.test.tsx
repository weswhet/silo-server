import { render, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { createWatchRouteRequest } from "./watchRouteHelpers";
import WatchRoute from "./WatchRoute";

const calls = vi.hoisted(() => ({ sync: vi.fn(), exit: vi.fn() }));
vi.mock("@/playback/watchPlaybackContext", async () => ({
  WatchPlaybackControllerContext: (await import("react")).createContext({
    syncRouteRequest: calls.sync,
    handleRouteExit: calls.exit,
  }),
}));

describe("watch route controller", () => {
  it("keeps the playlist position and request identity when navigation synchronizes the player", async () => {
    const expected = createWatchRouteRequest({
      contentId: "movie",
      playlistId: "playlist",
      playlistEntryId: "duplicate-2",
      restart: true,
      returnHref: "/playlists/playlist",
    });
    render(
      <MemoryRouter
        initialEntries={[
          {
            pathname: "/watch/movie",
            search: "?playlist=playlist&entry=duplicate-2&restart=1",
            state: { watchReturnHref: "/playlists/playlist" },
          },
        ]}
      >
        <Routes>
          <Route path="/watch/:id" element={<WatchRoute />} />
        </Routes>
      </MemoryRouter>,
    );
    await waitFor(() => expect(calls.sync).toHaveBeenCalledWith(expected));
  });
});
