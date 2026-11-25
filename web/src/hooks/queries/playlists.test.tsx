import { act, renderHook } from "@testing-library/react";
import { expect, it } from "vitest";
import { setAccessToken, setProfileId, setProfileToken } from "@/api/client";
import { usePlaylistAuthorityKey } from "./playlists";
it("updates mounted playlist observers even when the same profile proof is reinstalled", () => {
  setAccessToken("account");
  setProfileId("profile");
  setProfileToken("proof");
  const { result } = renderHook(() => usePlaylistAuthorityKey());
  const before = result.current;
  act(() => setProfileToken("proof"));
  expect(result.current).not.toBe(before);
});
