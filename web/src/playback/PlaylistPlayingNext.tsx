import { useEffect, useRef } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { resolvePlaylistEntry } from "@/api/v2/playlists";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useCurrentProfile } from "@/hooks/useCurrentProfile";
import { useT } from "@/i18n";
import type { WatchRouteRequest } from "@/pages/watchRouteHelpers";
import { PlayingNextScreen } from "@/player/components/PlayingNextScreen";
import { recordAutoAdvance } from "@/player/stillWatching";
import type { PlaybackStartTrigger } from "@/player/types";
import { useWatchPlaybackController } from "./watchPlaybackContext";

/** Resolve again at Play: a stale preview is never authority to play a title. */
export default function PlaylistPlayingNext({
  request,
  videoEnded,
  onClose,
}: {
  request: WatchRouteRequest;
  videoEnded: boolean;
  onClose: () => void;
}) {
  const t = useT();
  const { profile } = useCurrentProfile();
  const controller = useWatchPlaybackController();
  const active = useRef(true);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  const next = useQuery({
    queryKey: ["playlists", profile?.id, request.playlistId, "next", request.playlistEntryId],
    queryFn: () => resolvePlaylistEntry(request.playlistId!, request.playlistEntryId!, true),
    staleTime: 0,
  });
  const play = useMutation({
    mutationFn: async (trigger: PlaybackStartTrigger) => ({
      result: await resolvePlaylistEntry(request.playlistId!, request.playlistEntryId!, true),
      trigger,
    }),
    onSuccess: ({ result, trigger }) => {
      if (!active.current) return;
      if (!result.entry?.item_id) {
        onClose();
        return;
      }
      if (trigger === "automatic") recordAutoAdvance();
      controller.startPlayback(
        {
          contentId: result.entry.item_id,
          playlistId: request.playlistId,
          playlistEntryId: result.entry.id,
          restart: true,
          returnHref: request.returnHref,
        },
        trigger,
      );
    },
    onError: () => {
      if (active.current) toast.error(t("web.playlists.playbackFailed"));
    },
  });
  // Do not announce a cached title while its current access is being checked.
  const entry = next.isError || next.isFetching ? undefined : next.data?.entry;
  const item = entry?.item;
  const episode = item?.type === "episode";
  if (next.isFetching || next.isError || !entry?.item_id || !item) {
    return (
      <Dialog
        open
        onOpenChange={(open) => {
          if (!open) {
            active.current = false;
            onClose();
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("web.playlists.title")}</DialogTitle>
          </DialogHeader>
          <p role="status">
            {t(
              next.isFetching
                ? "common.loading"
                : next.isError
                  ? "web.playlists.playbackFailed"
                  : "web.playlists.finished",
            )}
          </p>
          {next.isError && <Button onClick={() => void next.refetch()}>{t("common.retry")}</Button>}
          <Button
            variant="outline"
            onClick={() => {
              active.current = false;
              onClose();
            }}
          >
            {t("common.back")}
          </Button>
        </DialogContent>
      </Dialog>
    );
  }
  return (
    <PlayingNextScreen
      seriesTitle={episode ? item?.series_title : item?.title}
      nextEpisode={
        entry?.item_id && item
          ? {
              contentId: entry.item_id,
              title: item.title,
              seasonNumber: item.season_number ?? 0,
              episodeNumber: item.episode_number ?? 0,
              runtime: item.runtime ?? 0,
              overview: item.overview,
              stillUrl: episode ? item.poster_url : item.backdrop_url,
              stillThumbhash: episode ? item.poster_thumbhash : item.backdrop_thumbhash,
              stillIsEpisodeStill: episode
                ? item.poster_is_episode_still
                : item.backdrop_is_episode_still,
              machineTranslatedFields: item.machine_translated_fields,
              airDate: item.release_date ?? null,
              watchState: episode
                ? { played: item.user_state?.played, position_seconds: item.position_seconds }
                : undefined,
              isMovie: !episode,
            }
          : undefined
      }
      continueWatchingItems={[]}
      videoEnded={
        videoEnded && !next.isFetching && !next.isError && !play.isPending && !play.isError
      }
      onPlayNow={
        entry?.item_id
          ? (trigger) => {
              if (!play.isPending) play.mutate(trigger);
            }
          : undefined
      }
      onPlayItem={() => undefined}
      onClose={() => {
        active.current = false;
        onClose();
      }}
    />
  );
}
