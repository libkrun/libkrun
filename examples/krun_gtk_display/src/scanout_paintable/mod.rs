mod imp;

use gtk::{
    cairo::{RectangleInt, Region},
    gdk::{self, MemoryFormat, MemoryTextureBuilder},
    glib,
    glib::Bytes,
    prelude::*,
    subclass::prelude::*,
};
use krun_display::{Rect, ResourceFormat};

glib::wrapper! {
    pub struct ScanoutPaintable(ObjectSubclass<imp::ScanoutPaintable>) @implements gdk::Paintable;
}

impl ScanoutPaintable {
    pub fn new(default_width: i32, default_height: i32) -> Self {
        glib::Object::builder()
            .property("default-width", default_width)
            .property("default-height", default_height)
            .build()
    }

    pub fn update(
        &self,
        buffer: Bytes,
        width: i32,
        height: i32,
        format: MemoryFormat,
        rect: Option<Rect>,
    ) {
        assert_eq!(buffer.len(), width as usize * height as usize * 4);
        let imp = self.imp();

        if let Some(rect) = rect {
            let damage = RectangleInt::new(
                rect.x as i32,
                rect.y as i32,
                rect.width as i32,
                rect.height as i32,
            );
            let mut region_ref = imp.update_region.borrow_mut();
            match *region_ref {
                Some(ref region) => {
                    let _ = region.union_rectangle(&damage);
                }
                None => {
                    *region_ref = Some(Region::create_rectangle(&damage));
                }
            }
        } else {
            imp.update_region.replace(None);
        }

        let builder = MemoryTextureBuilder::new()
            .set_width(width)
            .set_height(height)
            .set_format(format)
            .set_stride(width as usize * ResourceFormat::BYTES_PER_PIXEL)
            .set_bytes(Some(&buffer));

        let region_ref = imp.update_region.borrow();
        let builder = if let Some(ref region) = *region_ref {
            builder
                .set_update_region(Some(region))
                .set_update_texture(imp.texture.borrow().as_ref())
        } else {
            builder
        };

        let new_texture = builder.build();
        drop(region_ref);
        let old_texture = imp.texture.replace(Some(new_texture));

        self.invalidate_contents();
        if let Some(old_texture) = old_texture
            && old_texture.width() != width
            && old_texture.height() != height
        {
            self.invalidate_size();
        }
    }
}
