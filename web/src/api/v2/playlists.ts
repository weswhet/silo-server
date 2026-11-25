import { v2 } from "./request";
import { withETag } from "./etag";

export const getPlaylist = (id: string) => withETag("GET /api/v2/playlists/{id}", { path: { id } });
export const resolvePlaylistEntry = (id: string, entryId: string, after = false) =>
  v2("GET /api/v2/playlists/{id}/playback", {
    path: { id },
    query: { entry_id: entryId, after },
  });
