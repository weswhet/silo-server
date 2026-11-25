vi.mock("@/hooks/queries/playlists", () => ({ usePlaylistAuthorityKey: () => "owner" }));
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider, onlineManager } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createWatchRouteRequest } from "@/pages/watchRouteHelpers";
import PlaylistPlayingNext from "./PlaylistPlayingNext";

const mocks = vi.hoisted(() => ({ resolve: vi.fn(), start: vi.fn(), current: vi.fn() }));
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
vi.mock("@/hooks/useCurrentProfile", () => ({
  useCurrentProfile: () => ({ profile: { id: "profile" } }),
}));
vi.mock("./watchPlaybackContext", () => ({
  useWatchPlaybackController: () => ({ startPlayback: mocks.start }),
}));
vi.mock("@/player/components/PlayingNextScreen", () => ({
  PlayingNextScreen: ({
    nextEpisode,
    onPlayNow,
    onClose,
  }: {
    nextEpisode?: { title: string };
    onPlayNow?: (trigger: string) => void;
    onClose: () => void;
  }) => (
    <>
      <span>{nextEpisode?.title}</span>
      <button onClick={() => onPlayNow?.("viewer")} disabled={!onPlayNow}>
        Play next
      </button>
      <button onClick={onClose}>Close</button>
    </>
  ),
}));
const request = createWatchRouteRequest({
  contentId: "movie",
  playlistId: "list",
  playlistEntryId: "first",
  returnHref: "/playlists/list",
});
const entry = {
  id: "second",
  item_id: "movie",
  item: { title: "Movie", type: "movie" },
  available: true,
};
function setup() {
  const close = vi.fn();
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const view = render(
    <QueryClientProvider client={client}>
      <PlaylistPlayingNext request={request} videoEnded onClose={close} />
    </QueryClientProvider>,
  );
  return { close, client, ...view };
}
beforeEach(() => {
  vi.clearAllMocks();
  mocks.current.mockReturnValue(true);
});
describe("playlist continuation", () => {
  it("does not reveal a cached next title while rechecking profile access", () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    client.setQueryData(["playlists", "profile", "list", "next", "first"], { entry });
    mocks.resolve.mockImplementation(() => new Promise(() => undefined));
    render(
      <QueryClientProvider client={client}>
        <PlaylistPlayingNext request={request} videoEnded onClose={() => undefined} />
      </QueryClientProvider>,
    );
    expect(screen.queryByText("Movie")).not.toBeInTheDocument();
    expect(screen.queryByText("Play next")).not.toBeInTheDocument();
  });

  it("rechecks access at Play and retains a duplicate title's distinct entry", async () => {
    mocks.resolve.mockResolvedValue({ entry });
    const { client } = setup();
    await screen.findByText("Movie");
    fireEvent.click(screen.getByText("Play next"));
    await waitFor(() =>
      expect(mocks.start).toHaveBeenCalledWith(
        expect.objectContaining({
          contentId: "movie",
          playlistEntryId: "second",
          playlistId: "list",
          restart: true,
        }),
        "viewer",
      ),
    );
    expect(client.getMutationCache().getAll()[0]?.state.variables).toEqual({
      trigger: "viewer",
      authority: {
        serverOrigin: "https://test.invalid",
        authContextVersion: 1,
        profileId: "profile",
        profileTokenGeneration: 1,
      },
    });
    expect(mocks.resolve).toHaveBeenCalledTimes(2);
    expect(mocks.resolve).toHaveBeenLastCalledWith("list", "first", true);
  });
  it("stops when the recheck finds no accessible later entry", async () => {
    mocks.resolve.mockResolvedValueOnce({ entry }).mockResolvedValueOnce({ entry: null });
    const { close } = setup();
    await screen.findByText("Movie");
    fireEvent.click(screen.getByText("Play next"));
    await waitFor(() => expect(close).toHaveBeenCalled());
    expect(mocks.start).not.toHaveBeenCalled();
  });
  it("does not resume after the viewer closes an in-flight recheck", async () => {
    let resolve!: (value: unknown) => void;
    mocks.resolve.mockResolvedValueOnce({ entry }).mockImplementationOnce(
      () =>
        new Promise((done) => {
          resolve = done;
        }),
    );
    setup();
    await screen.findByText("Movie");
    fireEvent.click(screen.getByText("Play next"));
    await waitFor(() => expect(mocks.resolve).toHaveBeenCalledTimes(2));
    fireEvent.click(screen.getByText("Close"));
    await act(async () => {
      resolve({ entry });
    });
    expect(mocks.start).not.toHaveBeenCalled();
  });
});

afterEach(() => onlineManager.setOnline(true));
it.each(["offline", "disabled"])(
  "withholds a seeded successful preview when its mount is %s",
  (state) => {
    onlineManager.setOnline(state !== "offline");
    const client = new QueryClient({
      defaultOptions: {
        queries: { initialData: { entry }, retry: false, enabled: state !== "disabled" },
      },
    });
    render(
      <QueryClientProvider client={client}>
        <PlaylistPlayingNext request={request} videoEnded onClose={() => {}} />
      </QueryClientProvider>,
    );
    expect(screen.queryByText("Movie")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Play next" })).not.toBeInTheDocument();
  },
);

it("does not adopt a Play result after its authority generation changed", async () => {
  let finish!: (value: unknown) => void;
  mocks.resolve.mockResolvedValueOnce({ entry }).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  setup();
  await screen.findByText("Movie");
  fireEvent.click(screen.getByText("Play next"));
  await waitFor(() => expect(mocks.resolve).toHaveBeenCalledTimes(2));
  mocks.current.mockReturnValue(false);
  await act(async () => finish({ entry }));
  expect(mocks.start).not.toHaveBeenCalled();
});
