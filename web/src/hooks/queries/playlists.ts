import { useId, useSyncExternalStore } from "react";
import { useQuery } from "@tanstack/react-query";
import { subscribeProfileAuthority } from "@/api/client";
import { v2 } from "@/api/v2/request";
import { getPlaylist, playlistAuthorityKey } from "@/api/v2/playlists";
import { useCurrentProfile } from "@/hooks/useCurrentProfile";

const authoritySnapshot = () => JSON.stringify(playlistAuthorityKey());
export function usePlaylistAuthorityKey() {
  return useSyncExternalStore(subscribeProfileAuthority, authoritySnapshot, authoritySnapshot);
}

export function usePlaylistCapabilities() {
  return useQuery({
    queryKey: ["playlists", "capabilities"],
    queryFn: ({ signal }) => v2("GET /api/v2/playlists/capabilities", { signal }),
    retry: false,
    staleTime: 60_000,
  });
}
export function usePlaylists(enabled = true) {
  const { profile } = useCurrentProfile();
  return useQuery({
    queryKey: ["playlists", profile?.id, "list"],
    queryFn: ({ signal }) => v2("GET /api/v2/playlists", { signal }),
    enabled: enabled && !!profile,
  });
}
export function usePlaylist(id: string | undefined) {
  const view = useId();
  const authority = usePlaylistAuthorityKey();
  const { profile } = useCurrentProfile();
  return useQuery({
    queryKey: ["playlists", profile?.id, id, view, authority],
    queryFn: () => getPlaylist(id!),
    refetchOnMount: "always",
    retry: false,
    enabled: !!id && !!profile,
  });
}
