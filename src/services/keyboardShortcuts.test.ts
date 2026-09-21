import { describe, expect, it, vi } from "vitest";
import {
  handleAppShortcut,
  handleMediaKey,
  mediaKeyCommand,
  type AppShortcutEvent,
  type MediaKeyEvent,
} from "./keyboardShortcuts";

function keyboardEvent(key: string, overrides: Partial<AppShortcutEvent> = {}): AppShortcutEvent {
  return {
    key,
    ctrlKey: false,
    altKey: false,
    shiftKey: false,
    metaKey: false,
    preventDefault: vi.fn(),
    ...overrides,
  };
}

describe("app keyboard shortcuts", () => {
  it.each([
    "MediaPlayPause",
    "MediaTrackNext",
    "MediaTrackPrevious",
    "AudioVolumeUp",
    "AudioVolumeDown",
    "AudioVolumeMute",
    "Unidentified",
  ])("leaves the unused %s key untouched", (key) => {
    const event = keyboardEvent(key);
    const lock = vi.fn();

    expect(handleAppShortcut(event, lock)).toBe(false);
    expect(event.preventDefault).not.toHaveBeenCalled();
    expect(lock).not.toHaveBeenCalled();
  });

  it("keeps the exact Ctrl+L application shortcut", () => {
    const event = keyboardEvent("L", { ctrlKey: true });
    const lock = vi.fn();

    expect(handleAppShortcut(event, lock)).toBe(true);
    expect(event.preventDefault).toHaveBeenCalledOnce();
    expect(lock).toHaveBeenCalledOnce();
  });

  it.each([
    { altKey: true },
    { shiftKey: true },
    { metaKey: true },
  ])("does not claim modified Ctrl+L variants", (modifier) => {
    const event = keyboardEvent("l", { ctrlKey: true, ...modifier });

    expect(handleAppShortcut(event, vi.fn())).toBe(false);
    expect(event.preventDefault).not.toHaveBeenCalled();
  });
});

describe("Windows media-key compatibility", () => {
  it.each([
    ["MediaPlayPause", "play-pause"],
    ["MediaTrackNext", "next"],
    ["MediaTrackPrevious", "previous"],
    ["MediaStop", "stop"],
    ["AudioVolumeUp", "volume-up"],
    ["AudioVolumeDown", "volume-down"],
    ["AudioVolumeMute", "volume-mute"],
  ] as const)("maps the standard %s event", (key, expected) => {
    expect(mediaKeyCommand(keyboardEvent(key))).toBe(expected);
  });

  it.each([
    [176, "next"],
    [177, "previous"],
    [178, "stop"],
    [179, "play-pause"],
  ] as const)("falls back to Windows virtual-key %s", (keyCode, expected) => {
    expect(mediaKeyCommand({ ...keyboardEvent("Unidentified"), keyCode })).toBe(expected);
  });

  it("uses the physical code when a keypad reports an unidentified key name", () => {
    expect(mediaKeyCommand({
      ...keyboardEvent("Unidentified"),
      code: "MediaPlayPause",
    })).toBe("play-pause");
  });

  it("prevents WebView handling only after recognizing a media control", () => {
    const event: MediaKeyEvent = keyboardEvent("MediaPlayPause");
    const forward = vi.fn();

    expect(handleMediaKey(event, forward)).toBe(true);
    expect(event.preventDefault).toHaveBeenCalledOnce();
    expect(forward).toHaveBeenCalledWith("play-pause");
  });

  it("leaves ordinary and unknown keypad events untouched", () => {
    const event: MediaKeyEvent = keyboardEvent("F13");
    const forward = vi.fn();

    expect(handleMediaKey(event, forward)).toBe(false);
    expect(event.preventDefault).not.toHaveBeenCalled();
    expect(forward).not.toHaveBeenCalled();
  });
});
