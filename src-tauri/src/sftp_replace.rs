//! Minimal SFTP v3 posix-rename extension: ssh2 0.9's rename API cannot send it.
//! Dedicated subsystem channel on the existing authenticated session; never a shell.
use crate::{error::AppError, filemanager_edit::error};
use std::io::{Read, Write};
const EXTENSION: &[u8] = b"posix-rename@openssh.com";
const MAX_PACKET: usize = 64 * 1024;

fn io_failure(_: std::io::Error) -> AppError {
    error(
        "save_unconfirmed",
        "De SSH-overdracht is onderbroken. Opslaan kon niet worden bevestigd; herlaad het bestand na opnieuw verbinden.",
    )
}
fn malformed() -> AppError {
    error(
        "save_unconfirmed",
        "De server gaf een ongeldige SFTP-reactie. Controleer de serverinhoud voordat je opnieuw opslaat.",
    )
}
fn send(stream: &mut impl Write, packet: &[u8]) -> Result<(), AppError> {
    stream
        .write_all(&(packet.len() as u32).to_be_bytes())
        .map_err(io_failure)?;
    stream.write_all(packet).map_err(io_failure)
}
fn receive(stream: &mut impl Read) -> Result<Vec<u8>, AppError> {
    let mut size = [0; 4];
    stream.read_exact(&mut size).map_err(io_failure)?;
    let size = u32::from_be_bytes(size) as usize;
    if !(5..=MAX_PACKET).contains(&size) {
        return Err(malformed());
    }
    let mut packet = vec![0; size];
    stream.read_exact(&mut packet).map_err(io_failure)?;
    Ok(packet)
}
fn string(packet: &mut Vec<u8>, value: &[u8]) {
    packet.extend_from_slice(&(value.len() as u32).to_be_bytes());
    packet.extend_from_slice(value);
}
fn take_string<'a>(packet: &mut &'a [u8]) -> Result<&'a [u8], AppError> {
    if packet.len() < 4 {
        return Err(malformed());
    }
    let size = u32::from_be_bytes(packet[..4].try_into().unwrap()) as usize;
    if size > packet.len() - 4 {
        return Err(malformed());
    }
    let value = &packet[4..4 + size];
    *packet = &packet[4 + size..];
    Ok(value)
}

pub fn handshake(stream: &mut (impl Read + Write)) -> Result<(), AppError> {
    send(stream, &[1, 0, 0, 0, 3])?; // SSH_FXP_INIT, version 3
    let packet = receive(stream)?;
    if packet[..5] != [2, 0, 0, 0, 3] {
        return Err(malformed());
    }
    let mut extensions = &packet[5..];
    let mut supported = false;
    while !extensions.is_empty() {
        let name = take_string(&mut extensions)?;
        let version = take_string(&mut extensions)?;
        supported |= name == EXTENSION && version == b"1";
    }
    if !supported {
        return Err(error(
            "atomic_unsupported",
            "Deze server ondersteunt geen veilige atomische vervanging via SFTP. Het oorspronkelijke bestand blijft behouden.",
        ));
    }
    Ok(())
}

pub fn replace(
    stream: &mut (impl Read + Write),
    source: &str,
    destination: &str,
) -> Result<(), AppError> {
    let mut request = vec![200, 0, 0, 0, 1]; // SSH_FXP_EXTENDED, request 1
    string(&mut request, EXTENSION);
    string(&mut request, source.as_bytes());
    string(&mut request, destination.as_bytes());
    send(stream, &request)?;
    let response = receive(stream)?;
    if response.len() < 9 || response[..5] != [101, 0, 0, 0, 1] {
        return Err(malformed());
    }
    let code = u32::from_be_bytes(response[5..9].try_into().unwrap());
    if code != 0 {
        let mut failure = error(
            "replace_failed",
            "Het bestand kon niet atomisch worden vervangen. Controleer schrijfrechten en vrije schijfruimte.",
        );
        failure.technical_details = Some(format!("SFTP replace status: {code}"));
        return Err(failure);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Stream {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Stream {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(bytes)
        }
    }
    impl Write for Stream {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn stream(supported: bool, status: u32) -> Stream {
        let mut input = Vec::new();
        let mut version = vec![2, 0, 0, 0, 3];
        if supported {
            string(&mut version, EXTENSION);
            string(&mut version, b"1");
        }
        send(&mut input, &version).unwrap();
        let mut reply = vec![101, 0, 0, 0, 1];
        reply.extend_from_slice(&status.to_be_bytes());
        send(&mut input, &reply).unwrap();
        Stream {
            input: std::io::Cursor::new(input),
            output: vec![],
        }
    }
    #[test]
    fn requires_posix_extension_and_encodes_names_as_binary_strings() {
        assert!(handshake(&mut stream(false, 0)).is_err());
        let mut io = stream(true, 0);
        handshake(&mut io).unwrap();
        replace(&mut io, "/site/.temp", "/site/a ' $; 中文.php").unwrap();
        assert!(io.output.windows(EXTENSION.len()).any(|x| x == EXTENSION));
        let mut denied = stream(true, 3);
        handshake(&mut denied).unwrap();
        let failure = replace(&mut denied, "a", "b").unwrap_err();
        assert_eq!(failure.category, "filemanager_replace_failed");
        assert_eq!(
            failure.technical_details.as_deref(),
            Some("SFTP replace status: 3")
        );
    }
    #[test]
    fn rejects_oversized_and_incomplete_packets() {
        assert!(receive(&mut std::io::Cursor::new(u32::MAX.to_be_bytes())).is_err());
        let mut io = stream(true, 0);
        handshake(&mut io).unwrap();
        io.input = std::io::Cursor::new(vec![]);
        assert_eq!(
            replace(&mut io, "a", "b").unwrap_err().category,
            "filemanager_save_unconfirmed"
        );
    }
}
