import {
  captureProfileRequestContext,
  StaleApiRequestContextError,
  type ProfileRequestContextSnapshot,
} from "@/api/client";
import { v2 } from "./request";
import { withETag } from "./etag";

export type PlaylistAuthority = Pick<
  ProfileRequestContextSnapshot,
  "serverOrigin" | "authContextVersion" | "profileId" | "profileTokenGeneration"
>;

function ownerStamp(snapshot: ProfileRequestContextSnapshot): PlaylistAuthority {
  return {
    serverOrigin: snapshot.serverOrigin,
    authContextVersion: snapshot.authContextVersion,
    profileId: snapshot.profileId,
    profileTokenGeneration: snapshot.profileTokenGeneration,
  };
}

/** Nonsecret owner identity only; safe for query data and mutation variables. */
export function capturePlaylistAuthority(): PlaylistAuthority | null {
  const snapshot = captureProfileRequestContext();
  return snapshot ? ownerStamp(snapshot) : null;
}
export function isPlaylistAuthorityCurrent(authority: PlaylistAuthority | null | undefined) {
  const current = capturePlaylistAuthority();
  return (
    !!authority &&
    !!current &&
    authority.serverOrigin === current.serverOrigin &&
    authority.authContextVersion === current.authContextVersion &&
    authority.profileId === current.profileId &&
    authority.profileTokenGeneration === current.profileTokenGeneration
  );
}
export function playlistAuthorityKey() {
  const authority = capturePlaylistAuthority();
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
  return { ...result, authority: ownerStamp(authority) };
};
export const resolvePlaylistEntry = async (id: string, entryId: string, after = false) => {
  const authority = requireAuthority();
  const result = await v2("GET /api/v2/playlists/{id}/playback", {
    path: { id },
    query: { entry_id: entryId, after },
    profileContext: authority,
  });
  if (!isPlaylistAuthorityCurrent(authority)) throw new StaleApiRequestContextError();
  return { ...result, authority: ownerStamp(authority) };
};
