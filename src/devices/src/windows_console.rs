use windows_sys::Win32::{
    System::Console::{
        INPUT_RECORD, KEY_EVENT, LEFT_ALT_PRESSED, LEFT_CTRL_PRESSED, RIGHT_ALT_PRESSED,
        RIGHT_CTRL_PRESSED, SHIFT_PRESSED,
    },
    UI::Input::KeyboardAndMouse::{
        VK_DELETE, VK_DOWN, VK_END, VK_F1, VK_F2, VK_F3, VK_F4, VK_F5, VK_F6, VK_F7, VK_F8, VK_F9,
        VK_F10, VK_F11, VK_F12, VK_HOME, VK_INSERT, VK_LEFT, VK_NEXT, VK_PRIOR, VK_RIGHT, VK_SPACE,
        VK_TAB, VK_UP,
    },
};

#[derive(Default)]
pub struct ConsoleInputDecoder {
    utf16: Vec<u16>,
}

impl ConsoleInputDecoder {
    pub fn decode(&mut self, records: &[INPUT_RECORD]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for record in records {
            if record.EventType != KEY_EVENT as u16 {
                continue;
            }
            let key = unsafe { record.Event.KeyEvent };
            if key.bKeyDown == 0 {
                continue;
            }
            let character = unsafe { key.uChar.UnicodeChar };
            if key.wVirtualKeyCode == VK_TAB && key.dwControlKeyState & SHIFT_PRESSED != 0 {
                append_utf16(&mut bytes, &mut self.utf16, false, false);
                append_shift_tab(&mut bytes, key.wRepeatCount);
            } else if character != 0 {
                let alt_pressed =
                    key.dwControlKeyState & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED) != 0;
                let alt_gr_pressed = key.dwControlKeyState
                    & (LEFT_CTRL_PRESSED | RIGHT_ALT_PRESSED)
                    == (LEFT_CTRL_PRESSED | RIGHT_ALT_PRESSED);
                if alt_pressed && !alt_gr_pressed {
                    append_utf16(&mut bytes, &mut self.utf16, false, true);
                }
                self.utf16
                    .extend(std::iter::repeat_n(character, key.wRepeatCount as usize));
                if alt_pressed && !alt_gr_pressed {
                    append_utf16(&mut bytes, &mut self.utf16, true, true);
                }
            } else if key.wVirtualKeyCode == VK_SPACE
                && key.dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED) != 0
            {
                append_utf16(&mut bytes, &mut self.utf16, false, false);
                bytes.extend(std::iter::repeat_n(0, key.wRepeatCount as usize));
            } else {
                append_utf16(&mut bytes, &mut self.utf16, false, false);
                append_virtual_key(
                    &mut bytes,
                    key.wVirtualKeyCode,
                    key.dwControlKeyState,
                    key.wRepeatCount,
                );
            }
        }
        append_utf16(&mut bytes, &mut self.utf16, false, true);
        bytes
    }
}

fn append_utf16(bytes: &mut Vec<u8>, utf16: &mut Vec<u16>, escape: bool, retain_trailing: bool) {
    let end =
        utf16.len() - usize::from(retain_trailing && matches!(utf16.last(), Some(0xd800..=0xdbff)));
    for character in char::decode_utf16(utf16.drain(..end)) {
        let character = character.unwrap_or(char::REPLACEMENT_CHARACTER);
        let mut encoded = [0; 4];
        if escape {
            bytes.push(b'\x1b');
        }
        bytes.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
    }
}

fn append_virtual_key(bytes: &mut Vec<u8>, key: u16, state: u32, repeat: u16) {
    let modifier = 1
        + u8::from(state & SHIFT_PRESSED != 0)
        + 2 * u8::from(state & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED) != 0)
        + 4 * u8::from(state & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED) != 0);
    let (prefix, suffix) = match key {
        VK_UP => (None, b'A'),
        VK_DOWN => (None, b'B'),
        VK_RIGHT => (None, b'C'),
        VK_LEFT => (None, b'D'),
        VK_HOME => (None, b'H'),
        VK_END => (None, b'F'),
        VK_INSERT => (Some(2), b'~'),
        VK_DELETE => (Some(3), b'~'),
        VK_PRIOR => (Some(5), b'~'),
        VK_NEXT => (Some(6), b'~'),
        VK_F1 => (Some(1), b'P'),
        VK_F2 => (Some(1), b'Q'),
        VK_F3 => (Some(1), b'R'),
        VK_F4 => (Some(1), b'S'),
        VK_F5 => (Some(15), b'~'),
        VK_F6 => (Some(17), b'~'),
        VK_F7 => (Some(18), b'~'),
        VK_F8 => (Some(19), b'~'),
        VK_F9 => (Some(20), b'~'),
        VK_F10 => (Some(21), b'~'),
        VK_F11 => (Some(23), b'~'),
        VK_F12 => (Some(24), b'~'),
        _ => return,
    };
    for _ in 0..repeat {
        if modifier == 1 && prefix == Some(1) && (b'P'..=b'S').contains(&suffix) {
            bytes.extend_from_slice(b"\x1bO");
            bytes.push(suffix);
            continue;
        }
        bytes.extend_from_slice(b"\x1b[");
        if let Some(prefix) = prefix {
            if prefix >= 10 {
                bytes.push(b'0' + prefix / 10);
            }
            bytes.push(b'0' + prefix % 10);
        } else if modifier != 1 {
            bytes.push(b'1');
        }
        if modifier != 1 {
            bytes.push(b';');
            bytes.push(b'0' + modifier);
        }
        bytes.push(suffix);
    }
}

fn append_shift_tab(bytes: &mut Vec<u8>, repeat: u16) {
    for _ in 0..repeat {
        bytes.extend_from_slice(b"\x1b[Z");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::{
        System::Console::{INPUT_RECORD_0, KEY_EVENT_RECORD, KEY_EVENT_RECORD_0},
        UI::Input::KeyboardAndMouse::{VK_F1, VK_F5, VK_LEFT, VK_UP},
    };

    fn key_event(character: u16, state: u32) -> INPUT_RECORD {
        INPUT_RECORD {
            EventType: KEY_EVENT as u16,
            Event: INPUT_RECORD_0 {
                KeyEvent: KEY_EVENT_RECORD {
                    bKeyDown: 1,
                    wRepeatCount: 1,
                    wVirtualKeyCode: 0,
                    wVirtualScanCode: 0,
                    uChar: KEY_EVENT_RECORD_0 {
                        UnicodeChar: character,
                    },
                    dwControlKeyState: state,
                },
            },
        }
    }

    #[test]
    fn translates_virtual_keys_and_modifiers() {
        let mut bytes = Vec::new();
        append_virtual_key(&mut bytes, VK_UP, 0, 1);
        append_virtual_key(&mut bytes, VK_LEFT, LEFT_CTRL_PRESSED, 1);
        append_virtual_key(&mut bytes, VK_F1, 0, 1);
        append_virtual_key(&mut bytes, VK_F5, SHIFT_PRESSED, 2);
        assert_eq!(bytes, b"\x1b[A\x1b[1;5D\x1bOP\x1b[15;2~\x1b[15;2~");
    }

    #[test]
    fn encodes_utf16_as_utf8() {
        let mut bytes = Vec::new();
        let mut utf16 = vec![b'a' as u16, 0xd83d, 0xde00, 0xd800];
        append_utf16(&mut bytes, &mut utf16, false, true);
        assert_eq!(bytes, b"a\xf0\x9f\x98\x80");
        assert_eq!(utf16, [0xd800]);
    }

    #[test]
    fn encodes_alt_surrogate_pair_across_records() {
        let mut decoder = ConsoleInputDecoder::default();
        let first = key_event(0xd83d, LEFT_ALT_PRESSED);
        let second = key_event(0xde00, LEFT_ALT_PRESSED);
        assert!(decoder.decode(&[first]).is_empty());
        assert_eq!(decoder.decode(&[second]), b"\x1b\xf0\x9f\x98\x80");
    }

    #[test]
    fn alt_does_not_modify_preceding_character() {
        let mut decoder = ConsoleInputDecoder::default();
        let records = [
            key_event(b'a' as u16, 0),
            key_event(b'b' as u16, LEFT_ALT_PRESSED),
        ];
        assert_eq!(decoder.decode(&records), b"a\x1bb");
    }
}
