import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, Play, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { v2, V2ProblemError } from "@/api/v2/request";
import { resolvePlaylistEntry } from "@/api/v2/playlists";
import { usePlaylist, usePlaylistCapabilities, usePlaylists } from "@/hooks/queries/playlists";
import { useCurrentProfile } from "@/hooks/useCurrentProfile";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import { useWatchPlaybackController } from "@/playback/watchPlaybackContext";
import { PageHeader } from "@/components/page/PageHeader";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useT } from "@/i18n";

export default function Playlists() {
  const t = useT();
  useDocumentTitle(t("web.playlists.title"));
  const { profile } = useCurrentProfile();
  const { id } = useParams();
  return <PlaylistPage key={`${profile?.id}:${id ?? ""}`} />;
}
function PlaylistPage() {
  const t = useT();
  const { id } = useParams();
  const navigate = useNavigate();
  const controller = useWatchPlaybackController();
  const qc = useQueryClient();
  const capabilities = usePlaylistCapabilities();
  const list = usePlaylists(capabilities.data?.available === true);
  const detail = usePlaylist(id);
  const [name, setName] = useState("");
  const [rename, setRename] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const edit = useMutation({
    mutationFn: (action: () => Promise<unknown>) => action(),
    onSuccess: () => {
      setError(null);
      void qc.invalidateQueries({ queryKey: ["playlists"] });
    },
    onError: (cause) => {
      setError(
        t(
          cause instanceof V2ProblemError && cause.status === 412
            ? "web.playlists.conflict"
            : "web.playlists.failed",
        ),
      );
      void qc.invalidateQueries({ queryKey: ["playlists"] });
    },
  });
  const play = useMutation({
    mutationFn: (entryId: string) => resolvePlaylistEntry(id!, entryId),
    onSuccess: ({ entry }) => {
      if (!entry?.item_id) {
        toast(t("web.playlists.finished"));
        return;
      }
      controller.startPlayback(
        {
          contentId: entry.item_id,
          playlistId: id,
          playlistEntryId: entry.id,
          restart: true,
          returnHref: `/playlists/${id}`,
        },
        "viewer",
      );
    },
    onError: () => toast.error(t("web.playlists.playbackFailed")),
  });
  const playlist = detail.data?.body;
  const headers = { "If-Match": detail.data?.etag ?? "" };
  function move(entryId: string, direction: number) {
    if (!playlist || !id) return;
    const ids = playlist.entries.map((entry) => entry.id);
    const index = ids.indexOf(entryId);
    const other = index + direction;
    if (index < 0 || other < 0 || other >= ids.length) return;
    [ids[index], ids[other]] = [ids[other]!, ids[index]!];
    edit.mutate(() =>
      v2("PUT /api/v2/playlists/{id}/entries/order", {
        path: { id },
        headers,
        body: { entry_ids: ids },
      }),
    );
  }
  return (
    <div className="space-y-6 py-6">
      <PageHeader
        title={playlist?.name ?? t("web.playlists.title")}
        subtitle={t("web.playlists.subtitle")}
      />
      {error && (
        <p role="alert" className="text-destructive">
          {error}
        </p>
      )}
      {capabilities.isPending ? (
        <p>{t("common.loading")}</p>
      ) : capabilities.data?.available !== true ? (
        <p role="alert">{t("web.playlists.loadFailed")}</p>
      ) : id ? (
        <>
          <Link to="/playlists" className="text-primary underline">
            {t("web.playlists.title")}
          </Link>
          {detail.isPending && <p>{t("common.loading")}</p>}
          {detail.isError && (
            <Button variant="outline" onClick={() => void detail.refetch()}>
              {t("common.retry")}
            </Button>
          )}
          {playlist && (
            <>
              <form
                className="flex flex-wrap items-end gap-2"
                onSubmit={(event) => {
                  event.preventDefault();
                  edit.mutate(async () => {
                    await v2("PATCH /api/v2/playlists/{id}", {
                      path: { id },
                      headers,
                      body: { name: (rename ?? playlist.name).trim() },
                    });
                    setRename(null);
                  });
                }}
              >
                <label className="grid gap-2">
                  {t("web.playlists.name")}
                  <Input
                    value={rename ?? playlist.name}
                    maxLength={200}
                    onChange={(event) => setRename(event.target.value)}
                  />
                </label>
                <Button
                  type="submit"
                  disabled={edit.isPending || !(rename ?? playlist.name).trim()}
                >
                  {t("web.playlists.rename")}
                </Button>
                <Button
                  type="button"
                  variant="destructive"
                  disabled={edit.isPending}
                  onClick={() => setDeleting(true)}
                >
                  {t("web.playlists.delete")}
                </Button>
              </form>
              {!playlist.entries.length && (
                <p className="text-muted-foreground">{t("web.playlists.emptyEntries")}</p>
              )}
              <ol className="divide-border divide-y">
                {playlist.entries.map((entry, index) => (
                  <li key={entry.id} className="flex flex-wrap items-center gap-2 py-3">
                    <span className="min-w-0 flex-1">
                      <span dir="auto" className="block truncate">
                        {entry.available ? entry.item?.title : t("web.playlists.unavailable")}
                      </span>
                    </span>
                    <Button
                      size="icon"
                      variant="outline"
                      aria-label={t("web.detail.actions.play")}
                      disabled={!entry.available || play.isPending}
                      onClick={() => play.mutate(entry.id)}
                    >
                      <Play aria-hidden />
                    </Button>
                    <Button
                      size="icon"
                      variant="ghost"
                      aria-label={t("web.playlists.moveUp")}
                      disabled={edit.isPending || index === 0}
                      onClick={() => move(entry.id, -1)}
                    >
                      <ArrowUp aria-hidden />
                    </Button>
                    <Button
                      size="icon"
                      variant="ghost"
                      aria-label={t("web.playlists.moveDown")}
                      disabled={edit.isPending || index === playlist.entries.length - 1}
                      onClick={() => move(entry.id, 1)}
                    >
                      <ArrowDown aria-hidden />
                    </Button>
                    <Button
                      size="icon"
                      variant="ghost"
                      aria-label={t("web.playlists.remove")}
                      disabled={edit.isPending}
                      onClick={() =>
                        edit.mutate(() =>
                          v2("DELETE /api/v2/playlists/{id}/entries/{entry_id}", {
                            path: { id, entry_id: entry.id },
                            headers,
                          }),
                        )
                      }
                    >
                      <Trash2 aria-hidden />
                    </Button>
                  </li>
                ))}
              </ol>
              <ConfirmDialog
                open={deleting}
                onOpenChange={setDeleting}
                title={t("web.playlists.delete")}
                description={t("web.playlists.deleteDescription")}
                variant="destructive"
                isPending={edit.isPending}
                onConfirm={() =>
                  edit.mutate(async () => {
                    await v2("DELETE /api/v2/playlists/{id}", { path: { id }, headers });
                    navigate("/playlists");
                  })
                }
              />
            </>
          )}
        </>
      ) : (
        <>
          <form
            className="flex flex-wrap items-end gap-2"
            onSubmit={(event) => {
              event.preventDefault();
              edit.mutate(async () => {
                const created = await v2("POST /api/v2/playlists", { body: { name: name.trim() } });
                setName("");
                navigate(`/playlists/${created.id}`);
              });
            }}
          >
            <label className="grid gap-2">
              {t("web.playlists.name")}
              <Input
                value={name}
                maxLength={200}
                onChange={(event) => setName(event.target.value)}
              />
            </label>
            <Button type="submit" disabled={!name.trim() || edit.isPending}>
              <Plus aria-hidden />
              {t("web.playlists.create")}
            </Button>
          </form>
          {list.isPending && <p>{t("common.loading")}</p>}
          {list.isError && (
            <Button variant="outline" onClick={() => void list.refetch()}>
              {t("common.retry")}
            </Button>
          )}
          {list.data?.items.length === 0 && <p>{t("web.playlists.empty")}</p>}
          <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {list.data?.items.map((entry) => (
              <li key={entry.id}>
                <Link
                  to={`/playlists/${entry.id}`}
                  className="border-border hover:bg-accent block rounded-xl border p-5"
                >
                  <span dir="auto" className="block truncate font-semibold">
                    {entry.name}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
