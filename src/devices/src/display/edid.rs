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

    /// The pixel clock in 10 kHz steps, rounded to 100 kHz.
    ///
    /// The formula for getting refresh rate out of this value is:
    ///   refresh_rate = clk * 10000 / (htotal * vtotal)
    /// Solving for clk:
    ///   clk = (refresh_rate * htotal * vtotal) / 10000
    ///
    /// Pseudocode of kernel logic for vrefresh:
    ///    vtotal := mode->vtotal;
    ///    calc_val := (clock * 1000) / htotal
    ///    refresh := (calc_val + vtotal / 2) / vtotal
    ///    if flags & INTERLACE: refresh *= 2
    ///    if flags & DBLSCAN: refresh /= 2
    ///    if vscan > 1: refresh /= vscan
    fn clock(&self) -> u64 {
        let htotal = self.width as u64 + self.horizontal_blanking as u64;
        let vtotal = self.height as u64 + self.vertical_blanking as u64;
        let pixels = (self.refresh_rate as u64)
            .saturating_mul(htotal)
            .saturating_mul(vtotal);
        (pixels / 10000 + 5) / 10 * 10
    }

    pub fn bytes(self) -> Box<[u8]> {
        // A base-block detailed timing holds a 16-bit clock and 12-bit sizes. A
        // larger mode goes in a DisplayID extension, whose Type I timing holds
        // a 24-bit clock and 16-bit sizes, all stored minus one.
        let clock = self.clock();
        let in_base_block = self.width < 4096 && self.height < 4096 && clock <= u16::MAX as u64;
        let in_displayid = (1..=1 << 24).contains(&clock)
            && (1..=1 << 16).contains(&self.width)
            && (1..=1 << 16).contains(&self.height);
        let extensions = if !in_base_block && in_displayid { 1 } else { 0 };

        let mut edid_box: Box<[u8]> =
            vec![0; (1 + extensions) * EDID_DATA_LENGTH].into_boxed_slice();
        let (edid, extension) = edid_box.split_at_mut(EDID_DATA_LENGTH);

        populate_header(edid, &self.manufacturer);
        populate_edid_version(edid);
        populate_size(edid, &self);
        populate_standard_timings(edid, &self);

        // 4 available descriptor blocks. EDID 1.4 requires a timing in the
        // first, so for a guest that doesn't read DisplayID it holds the mode
        // divided by the smallest whole factor that fits, with its clock capped
        // (a lower refresh rate). Linux marks it preferred too, but sorts the
        // DisplayID mode first when the sizes match, and virtio-gpu drops a
        // preferred mode of another size.
        let factor = self.width.max(self.height) / 4096 + 1;
        let fallback = EdidInfo {
            width: (self.width / factor).max(1),
            height: (self.height / factor).max(1),
            ..self.clone()
        };
        populate_detailed_timing(&mut edid[54..72], &fallback);

        let block1 = &mut edid[72..90];
        populate_display_name(block1, &self.display_name);

        edid[126] = extensions as u8;
        calculate_checksum(edid);

        if extensions == 1 {
            populate_displayid(extension, &self);
            calculate_checksum(extension);
        }

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
    let clock = info.clock().min(u16::MAX as u64) as u16;
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

// A DisplayID 1.3 extension block with the mode as its one Type I detailed
// timing, marked preferred.
fn populate_displayid(extension: &mut [u8], info: &EdidInfo) {
    const TIMING_LENGTH: u8 = 20;
    const BLOCK_LENGTH: u8 = 3 + TIMING_LENGTH;

    extension[0] = 0x70; // DisplayID extension
    let section = &mut extension[1..];
    section[0] = 0x13; // version 1.3
    section[1] = BLOCK_LENGTH;
    section[2] = 0x00; // no product type
    section[3] = 0; // no further sections

    let block = &mut section[4..4 + BLOCK_LENGTH as usize];
    block[0] = 0x03; // Type I detailed timing
    block[1] = 0x00;
    block[2] = TIMING_LENGTH;
    let timing = &mut block[3..];
    timing[0..3].copy_from_slice(&(info.clock() as u32 - 1).to_le_bytes()[..3]);
    timing[3] = 0x88; // preferred, aspect ratio undefined
    let fields = [
        info.width,
        info.horizontal_blanking as u32,
        info.horizontal_front as u32,
        info.horizontal_sync as u32,
        info.height,
        info.vertical_blanking as u32,
        info.vertical_front as u32,
        info.vertical_sync as u32,
    ];
    for (i, field) in fields.into_iter().enumerate() {
        timing[4 + 2 * i..6 + 2 * i].copy_from_slice(&((field - 1) as u16).to_le_bytes());
    }

    let end = 4 + BLOCK_LENGTH as usize;
    let sum = section[..end].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    section[end] = sum.wrapping_neg();
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

    /// The base block's detailed timing as (clock in 10 kHz, width, height).
    fn base_block_mode(edid: &[u8]) -> (u64, u32, u32) {
        let dtd = &edid[54..72];
        let clock = u16::from_le_bytes([dtd[0], dtd[1]]);
        let width = dtd[2] as u32 | ((dtd[4] as u32 >> 4) << 8);
        let height = dtd[5] as u32 | ((dtd[7] as u32 >> 4) << 8);
        (clock as u64, width, height)
    }

    /// The pixel clock in 10 kHz, rounded to 100 kHz, with the default blanking.
    fn expected_clock(width: u32, height: u32, refresh_rate: u32) -> u64 {
        let pixels = (width as u64 + DEFAULT_HORIZONTAL_BLANKING as u64)
            * (height as u64 + DEFAULT_VERTICAL_BLANKING as u64);
        ((refresh_rate as u64).saturating_mul(pixels) / 10000 + 5) / 10 * 10
    }

    /// What a guest that doesn't read DisplayID gets: the size divided by the
    /// smallest whole factor that fits 12 bits, its clock capped at 16 bits.
    fn expected_base_block(width: u32, height: u32, refresh_rate: u32) -> (u64, u32, u32) {
        let factor = width.max(height) / 4096 + 1;
        let (width, height) = ((width / factor).max(1), (height / factor).max(1));
        let clock = expected_clock(width, height, refresh_rate).min(u16::MAX as u64);
        (clock, width, height)
    }

    /// The DisplayID extension's Type I timing as (clock in 10 kHz, width,
    /// height), or None without an extension.
    fn displayid_mode(edid: &[u8]) -> Option<(u64, u32, u32)> {
        if edid[126] == 0 {
            return None;
        }
        assert_eq!(edid[126], 1);
        let ext = &edid[128..256];
        assert_eq!(ext[0], 0x70);
        let section = &ext[1..];
        let section_length = section[1] as usize;
        assert_eq!(section_length, 23);
        let sum = section[..4 + section_length + 1]
            .iter()
            .fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0, "DisplayID section checksum");
        assert_eq!(section[4], 0x03, "Type I timing");
        let timing = &ext[8..];
        assert_eq!(timing[3] & 0x80, 0x80, "preferred");
        let field = |i: usize| u16::from_le_bytes([timing[i], timing[i + 1]]) as u32 + 1;
        let clock = u32::from_le_bytes([timing[0], timing[1], timing[2], 0]) as u64 + 1;
        Some((clock, field(4), field(12)))
    }

    #[test]
    fn modes_beyond_the_base_block() {
        for (width, height, refresh_rate) in [
            (1920, 1080, 60),
            (2560, 1440, 144),
            (2392, 1800, 120),
            (3024, 1964, 120),
            (3840, 2160, 60),
            (3840, 2160, 120),
            (3840, 2160, 144),
            (4096, 2160, 60),
            (5120, 2880, 60),
            (6016, 3384, 60),
            (7680, 4320, 60),
            (7680, 4320, 120),
            (8192, 8192, 60),
            (8192, 2, 60),
        ] {
            let params = EdidParams {
                refresh_rate,
                ..EdidParams::default()
            };
            let edid = EdidInfo::new(width, height, &params).bytes();

            for block in edid.chunks(EDID_DATA_LENGTH) {
                let sum = block.iter().fold(0u8, |a, &b| a.wrapping_add(b));
                assert_eq!(sum, 0, "{width}x{height}@{refresh_rate} checksum");
            }
            let mode = (expected_clock(width, height, refresh_rate), width, height);
            let base_block = base_block_mode(&edid);
            assert_eq!(
                displayid_mode(&edid).unwrap_or(base_block),
                mode,
                "{width}x{height}@{refresh_rate} preferred mode"
            );
            assert_eq!(
                base_block,
                expected_base_block(width, height, refresh_rate),
                "{width}x{height}@{refresh_rate} base block"
            );
        }
    }

    #[test]
    fn base_block_only_when_the_mode_fits() {
        let edid = EdidInfo::new(3840, 2160, &EdidParams::default()).bytes();
        assert_eq!(edid.len(), EDID_DATA_LENGTH);
        assert_eq!(edid[126], 0);
    }

    #[test]
    fn base_block_only_when_the_mode_fits_neither() {
        for (width, height, refresh_rate) in [
            (16384, 16384, 610),
            (65537, 1080, 60),
            (65536, 65536, u32::MAX),
        ] {
            let params = EdidParams {
                refresh_rate,
                ..EdidParams::default()
            };
            let edid = EdidInfo::new(width, height, &params).bytes();
            assert_eq!(edid.len(), EDID_DATA_LENGTH);
            assert_eq!(edid[126], 0);
            assert_eq!(
                base_block_mode(&edid),
                expected_base_block(width, height, refresh_rate)
            );
        }
    }
}
