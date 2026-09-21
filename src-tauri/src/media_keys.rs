const PLAY: u32 = 46;
const PAUSE: u32 = 47;
const PLAY_PAUSE: u32 = 14;
const NEXT_TRACK: u32 = 11;
const PREVIOUS_TRACK: u32 = 12;
const STOP: u32 = 13;
const VOLUME_MUTE: u32 = 8;
const VOLUME_DOWN: u32 = 9;
const VOLUME_UP: u32 = 10;

fn app_command_id(command: &str) -> Option<u32> {
    match command {
        "play" => Some(PLAY),
        "pause" => Some(PAUSE),
        "play-pause" => Some(PLAY_PAUSE),
        "next" => Some(NEXT_TRACK),
        "previous" => Some(PREVIOUS_TRACK),
        "stop" => Some(STOP),
        "volume-mute" => Some(VOLUME_MUTE),
        "volume-down" => Some(VOLUME_DOWN),
        "volume-up" => Some(VOLUME_UP),
        _ => None,
    }
}

#[tauri::command]
pub fn forward_media_key(command: String) -> Result<(), String> {
    let command_id = app_command_id(&command)
        .ok_or_else(|| "De media-opdracht wordt niet ondersteund.".to_string())?;
    forward_windows_app_command(command_id)
}

#[cfg(target_os = "windows")]
fn forward_windows_app_command(command_id: u32) -> Result<(), String> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FAPPCOMMAND_KEY, GetForegroundWindow, PostMessageW, WM_APPCOMMAND,
    };

    // WM_APPCOMMAND stores the command in the high word and the input source in
    // the low word. Sending it to the foreground top-level window lets
    // DefWindowProc route the command to Windows' shell/media handler.
    let target = unsafe { GetForegroundWindow() };
    if target.is_null() {
        return Err("Er is geen actief Windows-venster voor de media-opdracht.".to_string());
    }
    let lparam = ((command_id as isize) << 16) | FAPPCOMMAND_KEY as isize;
    let posted = unsafe { PostMessageW(target, WM_APPCOMMAND, target as usize, lparam) };
    if posted == 0 {
        return Err("Windows kon de media-opdracht niet doorsturen.".to_string());
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn forward_windows_app_command(_command_id: u32) -> Result<(), String> {
    Err("Media-opdrachten doorsturen wordt alleen op Windows ondersteund.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_explicit_media_commands() {
        assert_eq!(app_command_id("play-pause"), Some(14));
        assert_eq!(app_command_id("next"), Some(11));
        assert_eq!(app_command_id("previous"), Some(12));
        assert_eq!(app_command_id("volume-up"), Some(10));
        assert_eq!(app_command_id("F13"), None);
        assert_eq!(app_command_id("anything-else"), None);
    }
}
