import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { getPlaylist } from "@/api/v2/playlists";
import { v2, V2ProblemError } from "@/api/v2/request";
import { withETag } from "@/api/v2/etag";
import { usePlaylists } from "@/hooks/queries/playlists";
import { useCurrentProfile } from "@/hooks/useCurrentProfile";
import { useT } from "@/i18n";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export default function AddToPlaylistDialog({
  open,
  onOpenChange,
  contentId,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  contentId: string;
}) {
  const t = useT();
  const { profile } = useCurrentProfile();
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("web.playlists.add")}</DialogTitle>
          <DialogDescription>{t("web.playlists.subtitle")}</DialogDescription>
        </DialogHeader>
        {open && (
          <AddPanel key={profile?.id} contentId={contentId} onDone={() => onOpenChange(false)} />
        )}
      </DialogContent>
    </Dialog>
  );
}
function AddPanel({ contentId, onDone }: { contentId: string; onDone: () => void }) {
  const t = useT();
  const qc = useQueryClient();
  const list = usePlaylists();
  const [name, setName] = useState("");
  const [createdId, setCreatedId] = useState<string>();
  const add = useMutation({
    mutationFn: async (id?: string) => {
      const targetId = id ?? createdId;
      const snapshot = targetId
        ? await getPlaylist(targetId)
        : await withETag("POST /api/v2/playlists", { body: { name: name.trim() } });
      if (!targetId) setCreatedId(snapshot.body.id);
      await v2("POST /api/v2/playlists/{id}/entries", {
        path: { id: snapshot.body.id },
        headers: { "If-Match": snapshot.etag },
        body: { item_id: contentId },
      });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["playlists"] });
      toast.success(t("web.playlists.added"));
      onDone();
    },
    onError: (error) => {
      toast.error(
        t(
          error instanceof V2ProblemError && error.status === 412
            ? "web.playlists.conflict"
            : "web.playlists.failed",
        ),
      );
      void list.refetch();
    },
  });
  return (
    <div className="space-y-4">
      {list.isPending && <p>{t("common.loading")}</p>}
      {list.isError && <Button onClick={() => void list.refetch()}>{t("common.retry")}</Button>}
      <ul className="max-h-64 space-y-2 overflow-y-auto">
        {list.data?.items.map((playlist) => (
          <li key={playlist.id}>
            <Button
              className="w-full justify-start"
              variant="outline"
              disabled={add.isPending}
              onClick={() => add.mutate(playlist.id)}
            >
              <span className="truncate" dir="auto">
                {playlist.name}
              </span>
            </Button>
          </li>
        ))}
      </ul>
      <form
        className="grid gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          add.mutate(undefined);
        }}
      >
        <label className="grid gap-2">
          {t("web.playlists.name")}
          <Input
            value={name}
            maxLength={200}
            onChange={(event) => {
              setName(event.target.value);
              setCreatedId(undefined);
            }}
          />
        </label>
        <Button type="submit" disabled={!name.trim() || add.isPending}>
          {t("web.playlists.createAndAdd")}
        </Button>
      </form>
    </div>
  );
}
