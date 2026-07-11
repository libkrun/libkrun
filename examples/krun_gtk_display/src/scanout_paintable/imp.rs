use gtk::{
    cairo::Region,
    gdk::{Paintable, PaintableFlags, RGBA, Snapshot, Texture},
    glib,
    graphene::Rect,
    prelude::*,
    subclass::prelude::*,
};

use log::debug;
use std::cell::{Cell, RefCell};

#[derive(Default, glib::Properties)]
#[properties(wrapper_type = super::ScanoutPaintable)]
pub struct ScanoutPaintable {
    // Store the texture that this paintable will draw.
    pub texture: RefCell<Option<Texture>>,
    #[property(get, set)]
    pub default_width: Cell<i32>,
    #[property(get, set)]
    pub default_height: Cell<i32>,
    pub update_region: RefCell<Option<Region>>,
}

#[glib::object_subclass]
impl ObjectSubclass for ScanoutPaintable {
    const NAME: &'static str = "ScanoutPaintable";
    type Type = super::ScanoutPaintable;
    type Interfaces = (Paintable,);
}

#[glib::derived_properties]
impl ObjectImpl for ScanoutPaintable {
    fn dispose(&self) {
        debug!("ScanoutPaintable::dispose");
    }
}

impl PaintableImpl for ScanoutPaintable {
    fn snapshot(&self, snapshot: &Snapshot, width: f64, height: f64) {
        if let Some(texture) = self.texture.borrow().as_ref() {
            snapshot.append_texture(texture, &Rect::new(0.0, 0.0, width as f32, height as f32));
            self.update_region.replace(None);
        } else {
            snapshot.append_color(
                &RGBA::new(0.0, 0.0, 0.0, 1.0),
                &Rect::new(0.0, 0.0, width as f32, height as f32),
            );
        }
    }

    fn flags(&self) -> PaintableFlags {
        PaintableFlags::empty()
    }

    fn intrinsic_aspect_ratio(&self) -> f64 {
        if let Some(texture) = self.texture.borrow().as_ref() {
            texture.width() as f64 / texture.height() as f64
        } else {
            self.default_width.get() as f64 / self.default_height.get() as f64
        }
    }

    fn intrinsic_width(&self) -> i32 {
        self.texture
            .borrow()
            .as_ref()
            .map(|t| t.width())
            .unwrap_or(self.default_width.get())
    }

    fn intrinsic_height(&self) -> i32 {
        self.texture
            .borrow()
            .as_ref()
            .map(|t| t.height())
            .unwrap_or(self.default_height.get())
    }
}
