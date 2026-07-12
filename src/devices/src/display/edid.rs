// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of the EDID specification provided by software.
//! EDID spec: <https://glenwing.github.io/docs/VESA-EEDID-A2.pdf>

//! This module is used to create the Extended Display Identification Data (EDID), which will be
//! exposed to the guest system.
//!
//! We ignore most of the spec, the point here being for us to provide enough for graphics to work
//! and to allow us to configure the resolution and refresh rate (via the preferred timing mode
//! pixel clock).
//!
//! The EDID spec defines a number of methods to provide mode information, but in priority order the
//! "detailed" timing information is first, so we provide a single block of detailed timing
//! information and no other form of timing information.
//!
use super::types::{EdidParams, PhysicalSize};

const EDID_DATA_LENGTH: usize = 128;
const DEFAULT_HORIZONTAL_BLANKING: u16 = 560;
const DEFAULT_VERTICAL_BLANKING: u16 = 50;
const DEFAULT_HORIZONTAL_FRONT_PORCH: u16 = 64;
const DEFAULT_VERTICAL_FRONT_PORCH: u16 = 1;
const DEFAULT_HORIZONTAL_SYNC_PULSE: u16 = 192;
const DEFAULT_VERTICAL_SYNC_PULSE: u16 = 3;
const MILLIMETERS_PER_INCH: f32 = 25.4;

#[derive(Clone)]
pub struct EdidInfo {
    width: u32,
    height: u32,
    refresh_rate: u32,
    horizontal_blanking: u16,
    vertical_blanking: u16,
    horizontal_front: u16,
    vertical_front: u16,
    horizontal_sync: u16,
    vertical_sync: u16,
    width_millimeters: u16,
    height_millimeters: u16,
    manufacturer: [u8; 3],
    display_name: String,
}

impl EdidInfo {
    /// Only width, height and refresh rate are required for the graphics stack to work, so instead
    /// of pulling actual numbers from the system, we just use some typical values to populate other
    /// fields for now.
    pub fn new(width: u32, height: u32, params: &EdidParams) -> Self {
        let (width_millimeters, height_millimeters) = match params.physical_size {
            PhysicalSize::Dpi(dpi) => (
                ((width as f32 / dpi as f32) * MILLIMETERS_PER_INCH) as u16,
                ((height as f32 / dpi as f32) * MILLIMETERS_PER_INCH) as u16,
            ),
            PhysicalSize::DimensionsMillimeters(width, height) => (width, height),
        };

        Self {
            width,
            height,
            refresh_rate: params.refresh_rate,
            horizontal_blanking: DEFAULT_HORIZONTAL_BLANKING,
            vertical_blanking: DEFAULT_VERTICAL_BLANKING,
            horizontal_front: DEFAULT_HORIZONTAL_FRONT_PORCH,
            vertical_front: DEFAULT_VERTICAL_FRONT_PORCH,
            horizontal_sync: DEFAULT_HORIZONTAL_SYNC_PULSE,
            vertical_sync: DEFAULT_VERTICAL_SYNC_PULSE,
            width_millimeters,
            height_millimeters,
            manufacturer: params.manufacturer,
            display_name: params.display_name.clone(),
        }
    }

    pub fn width_centimeters(&self) -> u8 {
        (self.width_millimeters / 10) as u8
    }

    pub fn height_centimeters(&self) -> u8 {
        (self.height_millimeters / 10) as u8
    }

    pub fn bytes(self) -> Box<[u8]> {
        let mut edid_box: Box<[u8]> = vec![0; EDID_DATA_LENGTH].into_boxed_slice();
        let edid = &mut edid_box[..];

        populate_header(edid, &self.manufacturer);
        populate_edid_version(edid);
        populate_size(edid, &self);
        populate_standard_timings(edid, &self);

        // 4 available descriptor blocks
        let block0 = &mut edid[54..72];
        populate_detailed_timing(block0, &self);

        let block1 = &mut edid[72..90];
        populate_display_name(block1, &self.display_name);

        calculate_checksum(edid);

        edid_box
    }
}

fn populate_display_name(edid_block: &mut [u8], name: &str) {
    edid_block[0..5].clone_from_slice(&[0x00, 0x00, 0x00, 0xFC, 0x00]);
    // Section 3.10.3.4: 13-byte field, newline-terminated if shorter than 13 chars
    let mut product_name = [b' '; 13];
    let len = name.len().min(13);
    product_name[..len].copy_from_slice(&name.as_bytes()[..len]);
    if len < 13 {
        product_name[len] = b'\n';
    }
    edid_block[5..].clone_from_slice(&product_name);
}

fn populate_detailed_timing(edid_block: &mut [u8], info: &EdidInfo) {
    assert_eq!(edid_block.len(), 18);

    // Detailed timings
    //
    // 18 Byte Descriptors - 72 Bytes
    // The 72 bytes in this section are divided into four data fields. Each of the four data fields
    // are 18 bytes in length. These 18 byte data fields shall contain either detailed timing data
    // as described in Section 3.10.2 or other types of data as described in Section 3.10.3. The
    // addresses and the contents of the four 18 byte descriptors are shown in Table 3.20.
    //
    // We leave the bottom 6 bytes of this block purposefully empty.
    let horizontal_blanking_lsb: u8 = (info.horizontal_blanking & 0xFF) as u8;
    let horizontal_blanking_msb: u8 = ((info.horizontal_blanking >> 8) & 0x0F) as u8;

    let vertical_blanking_lsb: u8 = (info.vertical_blanking & 0xFF) as u8;
    let vertical_blanking_msb: u8 = ((info.vertical_blanking >> 8) & 0x0F) as u8;

    // The pixel clock is what controls the refresh timing information.
    //
    // The formula for getting refresh rate out of this value is:
    //   refresh_rate = clk * 10000 / (htotal * vtotal)
    // Solving for clk:
    //   clk = (refresh_rate * htotal * votal) / 10000
    //
    // where:
    //   clk - The setting here
    //   vtotal - Total lines
    //   htotal - Total pixels per line
    //
    // Value here is pixel clock + 10,000, in 10khz steps.
    //
    // Pseudocode of kernel logic for vrefresh:
    //    vtotal := mode->vtotal;
    //    calc_val := (clock * 1000) / htotal
    //    refresh := (calc_val + vtotal / 2) / vtotal
    //    if flags & INTERLACE: refresh *= 2
    //    if flags & DBLSCAN: refresh /= 2
    //    if vscan > 1: refresh /= vscan
    //
    let htotal = info.width + (info.horizontal_blanking as u32);
    let vtotal = info.height + (info.vertical_blanking as u32);
    let mut clock: u16 = ((info.refresh_rate * htotal * vtotal) / 10000) as u16;
    // Round to nearest 10khz.
    clock = ((clock + 5) / 10) * 10;
    edid_block[0..2].copy_from_slice(&clock.to_le_bytes());

    let width_lsb: u8 = (info.width & 0xFF) as u8;
    let width_msb: u8 = ((info.width >> 8) & 0x0F) as u8;

    // Horizointal Addressable Video in pixels.
    edid_block[2] = width_lsb;
    // Horizontal blanking in pixels.
    edid_block[3] = horizontal_blanking_lsb;
    // Upper bits of the two above vals.
    edid_block[4] = horizontal_blanking_msb | (width_msb << 4);

    let vertical_active: u32 = info.height;
    let vertical_active_lsb: u8 = (vertical_active & 0xFF) as u8;
    let vertical_active_msb: u8 = ((vertical_active >> 8) & 0x0F) as u8;

    // Vertical addressable video in *lines*
    edid_block[5] = vertical_active_lsb;
    // Vertical blanking in lines
    edid_block[6] = vertical_blanking_lsb;
    // Sigbits of the above.
    edid_block[7] = vertical_blanking_msb | (vertical_active_msb << 4);

    let horizontal_front_lsb: u8 = (info.horizontal_front & 0xFF) as u8; // least sig 8 bits
    let horizontal_front_msb: u8 = ((info.horizontal_front >> 8) & 0x03) as u8; // most sig 2 bits
    let horizontal_sync_lsb: u8 = (info.horizontal_sync & 0xFF) as u8; // least sig 8 bits
    let horizontal_sync_msb: u8 = ((info.horizontal_sync >> 8) & 0x03) as u8; // most sig 2 bits

    let vertical_front_lsb: u8 = (info.vertical_front & 0x0F) as u8; // least sig 4 bits
    let vertical_front_msb: u8 = ((info.vertical_front >> 8) & 0x0F) as u8; // most sig 2 bits
    let vertical_sync_lsb: u8 = (info.vertical_sync & 0xFF) as u8; // least sig 4 bits
    let vertical_sync_msb: u8 = ((info.vertical_sync >> 8) & 0x0F) as u8; // most sig 2 bits

    // Horizontal front porch in pixels.
    edid_block[8] = horizontal_front_lsb;
    // Horizontal sync pulse width in pixels.
    edid_block[9] = horizontal_sync_lsb;
    // LSB of vertical front porch and sync pulse
    edid_block[10] = vertical_sync_lsb | (vertical_front_lsb << 4);
    // Upper 2 bits of these values.
    edid_block[11] = vertical_sync_msb
        | (vertical_front_msb << 2)
        | (horizontal_sync_msb << 4)
        | (horizontal_front_msb << 6);

    let width_millimeters_lsb: u8 = (info.width_millimeters & 0xFF) as u8; // least sig 8 bits
    let width_millimeters_msb: u8 = ((info.width_millimeters >> 8) & 0xF) as u8; // most sig 4 bits

    let height_millimeters_lsb: u8 = (info.height_millimeters & 0xFF) as u8; // least sig 8 bits
    let height_millimeters_msb: u8 = ((info.height_millimeters >> 8) & 0xF) as u8; // most sig 4 bits

    edid_block[12] = width_millimeters_lsb;
    edid_block[13] = height_millimeters_lsb;
    edid_block[14] = height_millimeters_msb | (width_millimeters_msb << 4);
}

// The EDID header. This is defined by the EDID spec.
fn populate_header(edid: &mut [u8], manufacturer_name: &[u8; 3]) {
    edid[0] = 0x00;
    edid[1] = 0xFF;
    edid[2] = 0xFF;
    edid[3] = 0xFF;
    edid[4] = 0xFF;
    edid[5] = 0xFF;
    edid[6] = 0xFF;
    edid[7] = 0x00;

    // 00001 -> A, 00010 -> B, etc
    let manufacturer_id: u16 = manufacturer_name
        .iter()
        .map(|c| (c - b'A' + 1) & 0x1F)
        .fold(0u16, |res, lsb| (res << 5) | (lsb as u16));
    edid[8..10].copy_from_slice(&manufacturer_id.to_be_bytes());

    let manufacture_product_id: u16 = 1;
    edid[10..12].copy_from_slice(&manufacture_product_id.to_le_bytes());

    let serial_id: u32 = 1;
    edid[12..16].copy_from_slice(&serial_id.to_le_bytes());

    let manufacture_week: u8 = 30;
    edid[16] = manufacture_week;

    let manufacture_year: u32 = 2025;
    edid[17] = (manufacture_year - 1990u32) as u8;
}

// The standard timings are 8 timing modes with a lower priority (and different data format)
// than the 4 detailed timing modes.
fn populate_standard_timings(edid: &mut [u8], info: &EdidInfo) {
    const fn aspect_ratio(width: u32, height: u32) -> (u32, u32) {
        let divisor = gcd(width, height);
        (width / divisor, height / divisor)
    }

    const fn aspect_ratio_bits(width: u32, height: u32) -> u8 {
        match aspect_ratio(width, height) {
            (8, 5) => 0x0,
            (4, 3) => 0x1,
            (5, 4) => 0x2,
            (16, 9) => 0x3,
            _ => panic!("Not a standard aspect ratio"),
        }
    }

    const fn resolution(width: u32, height: u32) -> (u32, u32, u8) {
        (width, height, aspect_ratio_bits(width, height))
    }

    const RESOLUTIONS: [(u32, u32, u8); 8] = [
        resolution(800, 600),
        resolution(1280, 1024),
        resolution(1400, 1050),
        resolution(1440, 900),
        resolution(1600, 900),
        resolution(1680, 1050),
        resolution(1856, 1392),
        resolution(1920, 1200),
    ];

    let mut slot = 0;
    for (width, height, aspect_ratio_bits) in RESOLUTIONS {
        if width > info.width || height > info.height {
            continue;
        }
        edid[0x26 + (slot * 2)] = (width / 8 - 31) as u8;
        edid[0x27 + (slot * 2)] = aspect_ratio_bits << 6;
        slot += 1;
    }
    for i in slot..8 {
        edid[0x26 + (i * 2)] = 0x01;
        edid[0x27 + (i * 2)] = 0x01;
    }
}

// Per the EDID spec, needs to be 1 and 4.
fn populate_edid_version(edid: &mut [u8]) {
    edid[18] = 1;
    edid[19] = 4;
}

fn populate_size(edid: &mut [u8], info: &EdidInfo) {
    edid[21] = info.width_centimeters();
    edid[22] = info.height_centimeters();
}

fn calculate_checksum(edid: &mut [u8]) {
    let mut checksum: u8 = 0;
    for byte in edid.iter().take(EDID_DATA_LENGTH - 1) {
        checksum = checksum.wrapping_add(*byte);
    }

    if checksum != 0 {
        checksum = 255 - checksum + 1;
    }

    edid[127] = checksum;
}

const fn gcd(x: u32, y: u32) -> u32 {
    match y {
        0 => x,
        _ => gcd(y, x % y),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_edid(manufacturer: [u8; 3], display_name: &str) -> Box<[u8]> {
        let params = EdidParams {
            manufacturer,
            display_name: display_name.to_string(),
            ..EdidParams::default()
        };
        EdidInfo::new(1920, 1080, &params).bytes()
    }

    fn decode_manufacturer(edid: &[u8]) -> [u8; 3] {
        let id = u16::from_be_bytes([edid[8], edid[9]]);
        [
            b'A' + ((id >> 10) & 0x1F) as u8 - 1,
            b'A' + ((id >> 5) & 0x1F) as u8 - 1,
            b'A' + (id & 0x1F) as u8 - 1,
        ]
    }

    #[test]
    fn manufacturer_encoding() {
        assert_eq!(decode_manufacturer(&make_edid(*b"RHT", "x")), *b"RHT");
        assert_eq!(decode_manufacturer(&make_edid(*b"GGL", "x")), *b"GGL");
    }

    #[test]
    fn display_name_short_is_newline_terminated() {
        let name = &make_edid(*b"RHT", "Hello")[77..90];
        assert_eq!(&name[..5], b"Hello");
        assert_eq!(name[5], b'\n');
    }

    #[test]
    fn display_name_max_13_chars() {
        let name = &make_edid(*b"RHT", "1234567890123")[77..90];
        assert_eq!(name, b"1234567890123");
    }

    #[test]
    fn valid_checksum() {
        let edid = make_edid(*b"RHT", "test");
        let sum: u8 = edid.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);
    }

    #[test]
    fn header_and_version() {
        let edid = make_edid(*b"RHT", "test");
        assert_eq!(
            &edid[0..8],
            &[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]
        );
        assert_eq!((edid[18], edid[19]), (1, 4));
        assert_eq!(&edid[72..77], &[0x00, 0x00, 0x00, 0xFC, 0x00]);
    }

    // Android's PhysicalDisplayId is derived from the EDID manufacturer ID
    // (bytes 8-9) and a CityHash of the display name (descriptor 0xFC).
    // The Cuttlefish APEX IDC files hardcode hashes for manufacturer "GGL"
    // and display name "CrosvmDisplay". This test verifies our EDID produces
    // the exact bytes Android expects, so touch routing works without
    // modifying any Android code.
    #[test]
    fn crosvm_display_android_id_compatibility() {
        let edid = make_edid(*b"GGL", "CrosvmDisplay");

        // Android reads manufacturer ID as big-endian u16 from bytes 8-9.
        // GGL: G=7, G=7, L=12 → (7 << 10) | (7 << 5) | 12 = 0x1CEC
        let manufacturer_id = u16::from_be_bytes([edid[8], edid[9]]);
        assert_eq!(manufacturer_id, 0x1CEC);

        // Android extracts the display name from the 0xFC descriptor (bytes 77-90),
        // strips the newline terminator, and hashes via CityHash64. Verify the name
        // is stored verbatim so the hash will match.
        assert_eq!(&edid[77..90], b"CrosvmDisplay");
    }
}
