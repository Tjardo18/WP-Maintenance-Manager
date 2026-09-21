export interface AppShortcutEvent {
  key: string;
  ctrlKey: boolean;
  altKey: boolean;
  shiftKey: boolean;
  metaKey: boolean;
  preventDefault: () => void;
}

export type MediaKeyCommand =
  | "play"
  | "pause"
  | "play-pause"
  | "next"
  | "previous"
  | "stop"
  | "volume-up"
  | "volume-down"
  | "volume-mute";

export interface MediaKeyEvent {
  key: string;
  code?: string;
  keyCode?: number;
  which?: number;
  preventDefault: () => void;
}

const mediaKeyNames: Readonly<Record<string, MediaKeyCommand>> = {
  MediaPlay: "play",
  MediaPause: "pause",
  MediaPlayPause: "play-pause",
  PlayPause: "play-pause",
  MediaTrackNext: "next",
  MediaNextTrack: "next",
  MediaTrackPrevious: "previous",
  MediaPreviousTrack: "previous",
  MediaPrevTrack: "previous",
  MediaStop: "stop",
  AudioVolumeUp: "volume-up",
  AudioVolumeDown: "volume-down",
  AudioVolumeMute: "volume-mute",
};

const windowsMediaVirtualKeys: Readonly<Record<number, MediaKeyCommand>> = {
  173: "volume-mute",
  174: "volume-down",
  175: "volume-up",
  176: "next",
  177: "previous",
  178: "stop",
  179: "play-pause",
};

export function mediaKeyCommand(event: MediaKeyEvent): MediaKeyCommand | undefined {
  const namedCommand = mediaKeyNames[event.key] ?? (event.code ? mediaKeyNames[event.code] : undefined);
  if (namedCommand) return namedCommand;
  const virtualKey = event.keyCode || event.which;
  return virtualKey ? windowsMediaVirtualKeys[virtualKey] : undefined;
}

export function handleMediaKey(
  event: MediaKeyEvent,
  forward: (command: MediaKeyCommand) => void,
) {
  const command = mediaKeyCommand(event);
  if (!command) return false;
  event.preventDefault();
  forward(command);
  return true;
}

export function isAppLockShortcut(event: AppShortcutEvent) {
  return event.ctrlKey
    && !event.altKey
    && !event.shiftKey
    && !event.metaKey
    && event.key.toLowerCase() === "l";
}

export function handleAppShortcut(event: AppShortcutEvent, lock: () => void) {
  if (!isAppLockShortcut(event)) return false;
  event.preventDefault();
  lock();
  return true;
}
