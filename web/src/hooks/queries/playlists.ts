import { useQuery } from "@tanstack/react-query";
import { v2 } from "@/api/v2/request";
import { getPlaylist } from "@/api/v2/playlists";
import { useCurrentProfile } from "@/hooks/useCurrentProfile";

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
  const { profile } = useCurrentProfile();
  return useQuery({
    queryKey: ["playlists", profile?.id, id],
    queryFn: () => getPlaylist(id!),
    enabled: !!id && !!profile,
  });
}
