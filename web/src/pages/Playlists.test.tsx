import { act, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Playlists from "./Playlists";

const mocks = vi.hoisted(() => ({
  resolve: vi.fn(),
  start: vi.fn(),
  current: vi.fn(),
  detail: {
    data: {
      body: {
        id: "queue",
        name: "Private queue",
        entries: [{ id: "entry", available: true, item: { title: "Restricted title" } }],
      },
      etag: "1",
    },
    isFetching: false,
    isFetchedAfterMount: true,
    fetchStatus: "idle",
    isError: false,
    isPending: false,
    refetch: vi.fn(),
  },
}));
vi.mock("@/api/client", () => ({
  captureProfileRequestContext: () => ({}),
  isCapturedProfileAuthorityActive: mocks.current,
}));
vi.mock("@/api/v2/playlists", () => ({
  capturePlaylistAuthority: () => ({
    serverOrigin: "https://test.invalid",
    authContextVersion: 1,
    profileId: "profile",
    profileTokenGeneration: 1,
  }),
  isPlaylistAuthorityCurrent: mocks.current,
  playlistAuthorityKey: () => [],
  resolvePlaylistEntry: mocks.resolve,
}));
vi.mock("@/hooks/queries/playlists", () => ({
  usePlaylist: () => mocks.detail,
  usePlaylistCapabilities: () => ({ data: { available: true } }),
  usePlaylists: () => ({ data: { items: [] } }),
}));
vi.mock("@/hooks/useCurrentProfile", () => ({
  useCurrentProfile: () => ({ profile: { id: "profile" } }),
}));
vi.mock("@/hooks/useDocumentTitle", () => ({ useDocumentTitle: () => {} }));
vi.mock("@/playback/watchPlaybackContext", () => ({
  useWatchPlaybackController: () => ({ startPlayback: mocks.start }),
}));
function mount() {
  const client = new QueryClient();
  const view = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/playlists/queue"]}>
        <Routes>
          <Route path="/playlists/:id" element={<Playlists />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...view, client };
}
beforeEach(() => {
  vi.clearAllMocks();
  mocks.current.mockReturnValue(true);
  mocks.detail.isFetching = false;
  mocks.detail.fetchStatus = "idle";
  mocks.detail.isFetchedAfterMount = true;
  mocks.detail.isError = false;
});
describe("playlist detail authority", () => {
  it.each(["fetching", "denied", "paused", "unvalidated"])(
    "withholds cached names and cards while access is %s",
    (state) => {
      mocks.detail.isFetching = state === "fetching";
      mocks.detail.fetchStatus =
        state === "fetching" ? "fetching" : state === "paused" ? "paused" : "idle";
      mocks.detail.isFetchedAfterMount = state !== "unvalidated";
      mocks.detail.isError = state === "denied";
      mount();
      expect(screen.queryByText("Restricted title")).not.toBeInTheDocument();
      expect(screen.queryByText("Private queue")).not.toBeInTheDocument();
    },
  );
  it.each(["unmount", "authority"])(
    "does not launch a pending Play after %s changes",
    async (change) => {
      let finish!: (value: unknown) => void;
      mocks.resolve.mockReturnValue(
        new Promise((resolve) => {
          finish = resolve;
        }),
      );
      const view = mount();
      fireEvent.click(screen.getByRole("button", { name: "Play" }));
      await act(async () => {});
      expect(view.client.getMutationCache().getAll()[0]?.state.variables).toEqual({
        entryId: "entry",
        authority: {
          serverOrigin: "https://test.invalid",
          authContextVersion: 1,
          profileId: "profile",
          profileTokenGeneration: 1,
        },
      });
      if (change === "unmount") view.unmount();
      else mocks.current.mockReturnValue(false);
      await act(async () => finish({ entry: { id: "entry", item_id: "movie" } }));
      expect(mocks.start).not.toHaveBeenCalled();
    },
  );
});
