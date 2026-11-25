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
    isError: false,
    isPending: false,
    refetch: vi.fn(),
  },
}));
vi.mock("@/api/client", () => ({
  captureProfileRequestContext: () => ({}),
  isCapturedProfileAuthorityActive: mocks.current,
}));
vi.mock("@/api/v2/playlists", () => ({ resolvePlaylistEntry: mocks.resolve }));
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
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter initialEntries={["/playlists/queue"]}>
        <Routes>
          <Route path="/playlists/:id" element={<Playlists />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
beforeEach(() => {
  vi.clearAllMocks();
  mocks.current.mockReturnValue(true);
  mocks.detail.isFetching = false;
  mocks.detail.isError = false;
});
describe("playlist detail authority", () => {
  it.each(["fetching", "denied"])(
    "withholds cached names and cards while access is %s",
    (state) => {
      mocks.detail.isFetching = state === "fetching";
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
      if (change === "unmount") view.unmount();
      else mocks.current.mockReturnValue(false);
      await act(async () => finish({ entry: { id: "entry", item_id: "movie" } }));
      expect(mocks.start).not.toHaveBeenCalled();
    },
  );
});
