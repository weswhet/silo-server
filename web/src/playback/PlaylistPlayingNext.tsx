import { useEffect, useId, useRef } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { StaleApiRequestContextError } from "@/api/client";
import { toast } from "sonner";
import {
  resolvePlaylistEntry,
  isPlaylistAuthorityCurrent,
  capturePlaylistAuthority,
} from "@/api/v2/playlists";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { usePlaylistAuthorityKey } from "@/hooks/queries/playlists";
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
  const view = useId();
  const authority = usePlaylistAuthorityKey();
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
    queryKey: [
      "playlists",
      profile?.id,
      request.playlistId,
      "next",
      request.playlistEntryId,
      view,
      authority,
    ],
    queryFn: () => resolvePlaylistEntry(request.playlistId!, request.playlistEntryId!, true),
    staleTime: 0,
  });
  const play = useMutation({
    mutationFn: async ({
      trigger,
      authority,
    }: {
      trigger: PlaybackStartTrigger;
      authority: ReturnType<typeof capturePlaylistAuthority>;
    }) => {
      if (!isPlaylistAuthorityCurrent(authority)) throw new StaleApiRequestContextError();
      return {
        result: await resolvePlaylistEntry(request.playlistId!, request.playlistEntryId!, true),
        trigger,
      };
    },
    onSuccess: ({ result, trigger }, { authority }) => {
      if (
        !active.current ||
        !isPlaylistAuthorityCurrent(authority) ||
        !isPlaylistAuthorityCurrent(result.authority)
      )
        return;
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
  const validated =
    next.isFetchedAfterMount &&
    next.fetchStatus === "idle" &&
    !next.isError &&
    isPlaylistAuthorityCurrent(next.data?.authority);
  const entry = validated ? next.data?.entry : undefined;
  const item = entry?.item;
  const episode = item?.type === "episode";
  if (!validated || !entry?.item_id || !item) {
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
          <DialogDescription role="status">
            {t(
              !validated && !next.isError
                ? "common.loading"
                : next.isError
                  ? "web.playlists.playbackFailed"
                  : "web.playlists.finished",
            )}
          </DialogDescription>
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
      seriesTitle={episode ? item.series_title : item.title}
      nextEpisode={{
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
      }}
      continueWatchingItems={[]}
      videoEnded={videoEnded && !play.isPending && !play.isError}
      onPlayNow={(trigger) => {
        if (!play.isPending) play.mutate({ trigger, authority: capturePlaylistAuthority() });
      }}
      onPlayItem={() => undefined}
      onClose={() => {
        active.current = false;
        onClose();
      }}
    />
  );
}
