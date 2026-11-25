import {
  captureProfileRequestContext,
  isCapturedProfileAuthorityActive,
  getProfileTokenGeneration,
  StaleApiRequestContextError,
  type ProfileRequestContextSnapshot,
} from "@/api/client";
import { v2 } from "./request";
import { withETag } from "./etag";

export function isPlaylistAuthorityCurrent(
  authority: ProfileRequestContextSnapshot | null | undefined,
) {
  return (
    !!authority &&
    isCapturedProfileAuthorityActive(authority) &&
    authority.profileTokenGeneration === getProfileTokenGeneration()
  );
}
export function playlistAuthorityKey() {
  const authority = captureProfileRequestContext();
  return authority
    ? [
        authority.serverOrigin,
        authority.authContextVersion,
        authority.profileId,
        authority.profileTokenGeneration,
      ]
    : [];
}
function requireAuthority() {
  const authority = captureProfileRequestContext();
  if (!authority) throw new StaleApiRequestContextError();
  return authority;
}
export const getPlaylist = async (id: string) => {
  const authority = requireAuthority();
  const result = await withETag("GET /api/v2/playlists/{id}", {
    path: { id },
    profileContext: authority,
  });
  if (!isPlaylistAuthorityCurrent(authority)) throw new StaleApiRequestContextError();
  return { ...result, authority };
};
export const resolvePlaylistEntry = async (id: string, entryId: string, after = false) => {
  const authority = requireAuthority();
  const result = await v2("GET /api/v2/playlists/{id}/playback", {
    path: { id },
    query: { entry_id: entryId, after },
    profileContext: authority,
  });
  if (!isPlaylistAuthorityCurrent(authority)) throw new StaleApiRequestContextError();
  return { ...result, authority };
};
