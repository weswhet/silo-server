import { useContext, useEffect, useMemo } from "react";
import { useLocation, useNavigate, useParams, useSearchParams } from "react-router";
import { captureProfileRequestContext } from "@/api/client";
import { resolvePlaylistEntry, isPlaylistAuthorityCurrent } from "@/api/v2/playlists";
import { toast } from "sonner";
import { usePlaylistAuthorityKey } from "@/hooks/queries/playlists";
import { useT } from "@/i18n";
import { WatchPlaybackControllerContext } from "@/playback/watchPlaybackContext";
import { buildWatchRouteRequest, createWatchRouteRequest } from "./watchRouteHelpers";

/**
 * WatchRoute is a route controller only.
 * The app-level playback host owns the persistent player instance.
 */
export default function WatchRoute() {
  const navigate = useNavigate();
  const authorityKey = usePlaylistAuthorityKey();
  const t = useT();
  const controller = useContext(WatchPlaybackControllerContext);
  const syncRouteRequest = controller?.syncRouteRequest;
  const handleRouteExit = controller?.handleRouteExit;
  const stopPlayback = controller?.stopPlayback;
  const startPlayback = controller?.startPlayback;
  const location = useLocation();
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const request = useMemo(() => {
    if (!id) {
      return null;
    }

    const locationState = location.state as {
      watchReturnHref?: string;
      audioTrackIndex?: number;
      prePlaySubtitleMode?: "auto" | "off" | "explicit";
      prePlaySubtitleSelection?: {
        source: "embedded" | "external" | "downloaded";
        language?: string;
        codec?: string;
        label?: string;
        forced?: boolean;
        hearing_impaired?: boolean;
        external_subtitle_path?: string;
        downloaded_subtitle_id?: number;
      } | null;
      versionPicked?: boolean;
    } | null;

    return createWatchRouteRequest({
      ...buildWatchRouteRequest(id, searchParams),
      audioTrackIndex: locationState?.audioTrackIndex,
      prePlaySubtitleMode: locationState?.prePlaySubtitleMode,
      prePlaySubtitleSelection: locationState?.prePlaySubtitleSelection,
      versionPicked: locationState?.versionPicked,
      returnHref: locationState?.watchReturnHref,
    });
  }, [id, location.state, searchParams]);

  useEffect(() => {
    if (!syncRouteRequest || !request) {
      return;
    }

    if (!request.playlistId) {
      syncRouteRequest(request);
      return;
    }
    // A URL is not playback authority: history and refreshed links must resolve
    // their owner and cursor before the persistent host adopts any content.
    let active = true;
    const authority = captureProfileRequestContext();
    const isCurrent = () => active && !!authority && isPlaylistAuthorityCurrent(authority);
    const stop = () => {
      stopPlayback?.();
      navigate(`/playlists/${request.playlistId}`, { replace: true });
    };
    if (!request.playlistEntryId || !authority) {
      stop();
      return;
    }
    void resolvePlaylistEntry(request.playlistId, request.playlistEntryId)
      .then(({ entry, authority: resolvedAuthority }) => {
        if (!isCurrent() || !isPlaylistAuthorityCurrent(resolvedAuthority)) return;
        if (!entry?.item_id) {
          stop();
        } else if (entry.id === request.playlistEntryId && entry.item_id === request.contentId) {
          // Keep explicit multipart/version selection only for this same item.
          syncRouteRequest(request);
        } else {
          startPlayback?.(
            {
              contentId: entry.item_id,
              playlistId: request.playlistId,
              playlistEntryId: entry.id,
              restart: true,
              returnHref: `/playlists/${request.playlistId}`,
            },
            "automatic",
          );
        }
      })
      .catch(() => {
        if (!isCurrent()) return;
        toast.error(t("web.playlists.playbackFailed"));
        stop();
      });
    return () => {
      active = false;
    };
  }, [request, syncRouteRequest, startPlayback, stopPlayback, navigate, t, authorityKey]);

  useEffect(() => {
    if (!handleRouteExit || !request) {
      return;
    }

    return () => {
      handleRouteExit(request.requestKey);
    };
  }, [handleRouteExit, request]);

  return null;
}
