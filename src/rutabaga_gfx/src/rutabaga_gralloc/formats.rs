// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! formats: Utility file for dealing with DRM and VK formats, and canonical
//! size calculations.

use std::fmt;

#[cfg(feature = "vulkano")]
use vulkano::format::Format as VulkanFormat;
#[cfg(feature = "vulkano")]
use vulkano::image::ImageAspect as VulkanImageAspect;

use crate::rutabaga_gralloc::gralloc::ImageAllocationInfo;
use crate::rutabaga_gralloc::gralloc::ImageMemoryRequirements;
use crate::rutabaga_utils::*;

/*
 * This list is based on Sommelier / cros_gralloc guest userspace.  Formats that are never
 * used by guest userspace (i.e, DRM_FORMAT_RGB332) are left out for simplicity.
 */

pub const DRM_FORMAT_R8: [u8; 4] = *b"R8  ";

pub const DRM_FORMAT_RGB565: [u8; 4] = *b"RG16";
pub const DRM_FORMAT_BGR888: [u8; 4] = *b"BG24";

pub const DRM_FORMAT_XRGB8888: [u8; 4] = *b"XR24";
pub const DRM_FORMAT_XBGR8888: [u8; 4] = *b"XB24";

pub const DRM_FORMAT_ARGB8888: [u8; 4] = *b"AR24";
pub const DRM_FORMAT_ABGR8888: [u8; 4] = *b"AB24";

pub const DRM_FORMAT_XRGB2101010: [u8; 4] = *b"XR30";
pub const DRM_FORMAT_XBGR2101010: [u8; 4] = *b"XB30";
pub const DRM_FORMAT_ARGB2101010: [u8; 4] = *b"AR30";
pub const DRM_FORMAT_ABGR2101010: [u8; 4] = *b"AB30";

pub const DRM_FORMAT_ABGR16161616F: [u8; 4] = *b"AB4H";

pub const DRM_FORMAT_NV12: [u8; 4] = *b"NV12";
pub const DRM_FORMAT_YVU420: [u8; 4] = *b"YV12";

/// A [fourcc](https://en.wikipedia.org/wiki/FourCC) format identifier.
#[derive(Copy, Clone, Eq, PartialEq, Default)]
pub struct DrmFormat(pub u32);

/// Planar properties associated with each `DrmFormat`.  Copied from helpers.c in minigbm.
#[derive(Copy, Clone)]
pub struct PlanarLayout {
    pub num_planes: usize,
    horizontal_subsampling: [u32; 3],
    vertical_subsampling: [u32; 3],
    bytes_per_pixel: [u32; 3],
}

static PACKED_1BPP: PlanarLayout = PlanarLayout {
    num_planes: 1,
    horizontal_subsampling: [1, 0, 0],
    vertical_subsampling: [1, 0, 0],
    bytes_per_pixel: [1, 0, 0],
};

static PACKED_2BPP: PlanarLayout = PlanarLayout {
    num_planes: 1,
    horizontal_subsampling: [1, 0, 0],
    vertical_subsampling: [1, 0, 0],
    bytes_per_pixel: [2, 0, 0],
};

static PACKED_3BPP: PlanarLayout = PlanarLayout {
    num_planes: 1,
    horizontal_subsampling: [1, 0, 0],
    vertical_subsampling: [1, 0, 0],
    bytes_per_pixel: [3, 0, 0],
};

static PACKED_4BPP: PlanarLayout = PlanarLayout {
    num_planes: 1,
    horizontal_subsampling: [1, 0, 0],
    vertical_subsampling: [1, 0, 0],
    bytes_per_pixel: [4, 0, 0],
};

static PACKED_8BPP: PlanarLayout = PlanarLayout {
    num_planes: 1,
    horizontal_subsampling: [1, 0, 0],
    vertical_subsampling: [1, 0, 0],
    bytes_per_pixel: [8, 0, 0],
};

static BIPLANAR_YUV420: PlanarLayout = PlanarLayout {
    num_planes: 2,
    horizontal_subsampling: [1, 2, 0],
    vertical_subsampling: [1, 2, 0],
    bytes_per_pixel: [1, 2, 0],
};

static TRIPLANAR_YUV420: PlanarLayout = PlanarLayout {
    num_planes: 3,
    horizontal_subsampling: [1, 2, 2],
    vertical_subsampling: [1, 2, 2],
    bytes_per_pixel: [1, 1, 1],
};

impl DrmFormat {
    /// Constructs a format identifer using a fourcc byte sequence.
    #[inline(always)]
    pub fn new(a: u8, b: u8, c: u8, d: u8) -> DrmFormat {
        DrmFormat((a as u32) | ((b as u32) << 8) | ((c as u32) << 16) | ((d as u32) << 24))
    }

    /// Returns the fourcc code as a sequence of bytes.
    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 4] {
        let f = self.0;
        [f as u8, (f >> 8) as u8, (f >> 16) as u8, (f >> 24) as u8]
    }

    /// Returns the planar layout of the format.
    pub fn planar_layout(&self) -> RutabagaResult<PlanarLayout> {
        match self.to_bytes() {
            DRM_FORMAT_R8 => Ok(PACKED_1BPP),
            DRM_FORMAT_RGB565 => Ok(PACKED_2BPP),
            DRM_FORMAT_BGR888 => Ok(PACKED_3BPP),
            DRM_FORMAT_ABGR2101010
            | DRM_FORMAT_ABGR8888
            | DRM_FORMAT_XBGR2101010
            | DRM_FORMAT_XBGR8888
            | DRM_FORMAT_ARGB2101010
            | DRM_FORMAT_ARGB8888
            | DRM_FORMAT_XRGB2101010
            | DRM_FORMAT_XRGB8888 => Ok(PACKED_4BPP),
            DRM_FORMAT_ABGR16161616F => Ok(PACKED_8BPP),
            DRM_FORMAT_NV12 => Ok(BIPLANAR_YUV420),
            DRM_FORMAT_YVU420 => Ok(TRIPLANAR_YUV420),
            _ => Err(RutabagaError::InvalidGrallocDrmFormat),
        }
    }

    #[cfg(feature = "vulkano")]
    /// Returns the Vulkan format from the DrmFormat.
    pub fn vulkan_format(&self) -> RutabagaResult<VulkanFormat> {
        match self.to_bytes() {
            DRM_FORMAT_R8 => Ok(VulkanFormat::R8_UNORM),
            DRM_FORMAT_RGB565 => Ok(VulkanFormat::R5G6B5_UNORM_PACK16),
            DRM_FORMAT_BGR888 => Ok(VulkanFormat::R8G8B8_UNORM),
            DRM_FORMAT_ABGR2101010 | DRM_FORMAT_XBGR2101010 => {
                Ok(VulkanFormat::A2R10G10B10_UNORM_PACK32)
            }
            DRM_FORMAT_ABGR8888 | DRM_FORMAT_XBGR8888 => Ok(VulkanFormat::R8G8B8A8_UNORM),
            DRM_FORMAT_ARGB2101010 | DRM_FORMAT_XRGB2101010 => {
                Ok(VulkanFormat::A2B10G10R10_UNORM_PACK32)
            }
            DRM_FORMAT_ARGB8888 | DRM_FORMAT_XRGB8888 => Ok(VulkanFormat::B8G8R8A8_UNORM),
            DRM_FORMAT_ABGR16161616F => Ok(VulkanFormat::R16G16B16A16_SFLOAT),
            DRM_FORMAT_NV12 => Ok(VulkanFormat::G8_B8R8_2PLANE_420_UNORM),
            DRM_FORMAT_YVU420 => Ok(VulkanFormat::G8_B8_R8_3PLANE_420_UNORM),
            _ => Err(RutabagaError::InvalidGrallocDrmFormat),
        }
    }

    #[cfg(feature = "vulkano")]
    /// Returns the Vulkan format from the DrmFormat.
    pub fn vulkan_image_aspect(&self, plane: usize) -> RutabagaResult<VulkanImageAspect> {
        match self.to_bytes() {
            DRM_FORMAT_R8
            | DRM_FORMAT_RGB565
            | DRM_FORMAT_BGR888
            | DRM_FORMAT_ABGR2101010
            | DRM_FORMAT_ABGR8888
            | DRM_FORMAT_XBGR2101010
            | DRM_FORMAT_XBGR8888
            | DRM_FORMAT_ARGB2101010
            | DRM_FORMAT_ARGB8888
            | DRM_FORMAT_XRGB2101010
            | DRM_FORMAT_XRGB8888 => Ok(VulkanImageAspect::Color),
            DRM_FORMAT_NV12 => match plane {
                0 => Ok(VulkanImageAspect::Plane0),
                1 => Ok(VulkanImageAspect::Plane1),
                _ => Err(RutabagaError::InvalidGrallocNumberOfPlanes),
            },
            DRM_FORMAT_YVU420 => match plane {
                0 => Ok(VulkanImageAspect::Plane0),
                1 => Ok(VulkanImageAspect::Plane1),
                2 => Ok(VulkanImageAspect::Plane2),
                _ => Err(RutabagaError::InvalidGrallocNumberOfPlanes),
            },
            _ => Err(RutabagaError::InvalidGrallocDrmFormat),
        }
    }
}

impl From<u32> for DrmFormat {
    fn from(u: u32) -> DrmFormat {
        DrmFormat(u)
    }
}

impl From<DrmFormat> for u32 {
    fn from(f: DrmFormat) -> u32 {
        f.0
    }
}

impl fmt::Debug for DrmFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let b = self.to_bytes();
        if b.iter().all(u8::is_ascii_graphic) {
            write!(
                f,
                "fourcc({}{}{}{})",
                b[0] as char, b[1] as char, b[2] as char, b[3] as char
            )
        } else {
            write!(
                f,
                "fourcc(0x{:02x}{:02x}{:02x}{:02x})",
                b[0], b[1], b[2], b[3]
            )
        }
    }
}

fn stride_from_layout(layout: &PlanarLayout, width: u32, plane: usize) -> RutabagaResult<u32> {
    let bytes_per_pixel = layout.bytes_per_pixel[plane];
    let horizontal_subsampling = layout.horizontal_subsampling[plane];
    let subsampled_width = checked_arithmetic!(width / horizontal_subsampling)?;
    let stride = checked_arithmetic!(bytes_per_pixel * subsampled_width)?;
    Ok(stride)
}

pub fn canonical_image_requirements(
    info: ImageAllocationInfo,
) -> RutabagaResult<ImageMemoryRequirements> {
    let mut image_requirements: ImageMemoryRequirements = Default::default();
    let mut size: u32 = 0;
    let layout = info.drm_format.planar_layout()?;
    for plane in 0..layout.num_planes {
        let plane_stride = stride_from_layout(&layout, info.width, plane)?;
        image_requirements.strides[plane] = plane_stride;
        if plane > 0 {
            image_requirements.offsets[plane] = size;
        }

        let height = info.height;
        let vertical_subsampling = layout.vertical_subsampling[plane];
        let subsampled_height = checked_arithmetic!(height / vertical_subsampling)?;
        let plane_size = checked_arithmetic!(subsampled_height * plane_stride)?;
        size = checked_arithmetic!(size + plane_size)?;
    }

    image_requirements.info = info;
    image_requirements.size = size as u64;
    Ok(image_requirements)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::*;
    use crate::rutabaga_gralloc::RutabagaGrallocFlags;

    #[test]
    fn format_debug() {
        let f = DrmFormat::new(b'X', b'R', b'2', b'4');
        let mut buf = String::new();
        write!(&mut buf, "{f:?}").unwrap();
        assert_eq!(buf, "fourcc(XR24)");

        let f = DrmFormat::new(0, 1, 2, 16);
        let mut buf = String::new();
        write!(&mut buf, "{f:?}").unwrap();
        assert_eq!(buf, "fourcc(0x00010210)");
    }

    #[test]
    fn canonical_formats() {
        let mut info = ImageAllocationInfo {
            width: 10,
            height: 10,
            drm_format: DrmFormat::new(b'R', b'8', b' ', b' '),
            flags: RutabagaGrallocFlags::empty(),
        };

        let r8_reqs = canonical_image_requirements(info).unwrap();

        assert_eq!(r8_reqs.info.width, 10);
        assert_eq!(r8_reqs.info.height, 10);
        assert_eq!(r8_reqs.strides[0], 10);
        assert_eq!(r8_reqs.strides[1], 0);
        assert_eq!(r8_reqs.strides[2], 0);

        assert_eq!(r8_reqs.offsets[0], 0);
        assert_eq!(r8_reqs.offsets[1], 0);
        assert_eq!(r8_reqs.offsets[2], 0);

        assert_eq!(r8_reqs.size, 100);

        info.drm_format = DrmFormat::new(b'X', b'R', b'2', b'4');
        let xr24_reqs = canonical_image_requirements(info).unwrap();

        assert_eq!(xr24_reqs.info.width, 10);
        assert_eq!(xr24_reqs.info.height, 10);
        assert_eq!(xr24_reqs.strides[0], 40);
        assert_eq!(xr24_reqs.strides[1], 0);
        assert_eq!(xr24_reqs.strides[2], 0);

        assert_eq!(xr24_reqs.offsets[0], 0);
        assert_eq!(xr24_reqs.offsets[1], 0);
        assert_eq!(xr24_reqs.offsets[2], 0);

        assert_eq!(xr24_reqs.size, 400);
    }

    #[test]
    fn canonical_planar_formats() {
        let mut info = ImageAllocationInfo {
            width: 10,
            height: 10,
            drm_format: DrmFormat::new(b'N', b'V', b'1', b'2'),
            flags: RutabagaGrallocFlags::empty(),
        };

        let nv12_reqs = canonical_image_requirements(info).unwrap();

        assert_eq!(nv12_reqs.info.width, 10);
        assert_eq!(nv12_reqs.info.height, 10);
        assert_eq!(nv12_reqs.strides[0], 10);
        assert_eq!(nv12_reqs.strides[1], 10);
        assert_eq!(nv12_reqs.strides[2], 0);

        assert_eq!(nv12_reqs.offsets[0], 0);
        assert_eq!(nv12_reqs.offsets[1], 100);
        assert_eq!(nv12_reqs.offsets[2], 0);

        assert_eq!(nv12_reqs.size, 150);

        info.drm_format = DrmFormat::new(b'Y', b'V', b'1', b'2');
        let yv12_reqs = canonical_image_requirements(info).unwrap();

        assert_eq!(yv12_reqs.info.width, 10);
        assert_eq!(yv12_reqs.info.height, 10);
        assert_eq!(yv12_reqs.strides[0], 10);
        assert_eq!(yv12_reqs.strides[1], 5);
        assert_eq!(yv12_reqs.strides[2], 5);

        assert_eq!(yv12_reqs.offsets[0], 0);
        assert_eq!(yv12_reqs.offsets[1], 100);
        assert_eq!(yv12_reqs.offsets[2], 125);

        assert_eq!(yv12_reqs.size, 150);
    }
}
