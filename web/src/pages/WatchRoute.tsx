import { useContext, useEffect, useMemo } from "react";
import { useLocation, useParams, useSearchParams } from "react-router";
import { WatchPlaybackControllerContext } from "@/playback/watchPlaybackContext";
import { buildWatchRouteRequest, createWatchRouteRequest } from "./watchRouteHelpers";

/**
 * WatchRoute is a route controller only.
 * The app-level playback host owns the persistent player instance.
 */
export default function WatchRoute() {
  const controller = useContext(WatchPlaybackControllerContext);
  const syncRouteRequest = controller?.syncRouteRequest;
  const handleRouteExit = controller?.handleRouteExit;
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

    syncRouteRequest(request);
  }, [request, syncRouteRequest]);

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
