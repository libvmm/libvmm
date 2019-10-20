use super::bitmap::Bitmap;
use crate::{AlignedAddress, PAGE_4K, SHIFT_4K};

pub struct IOBitmap {
    pub a: Bitmap,
    pub b: Bitmap,
}

impl IOBitmap {
    const RANGE_B: u16 = 0x8000;

    pub unsafe fn new_raw(a: u64, b: u64) -> Option<Self> {
        if !a.aligned(SHIFT_4K) || !b.aligned(SHIFT_4K) {
            return None;
        }

        let mut iobitmap = IOBitmap {
            a: Bitmap::new_raw(a, PAGE_4K).unwrap(),
            b: Bitmap::new_raw(b, PAGE_4K).unwrap(),
        };

        iobitmap.intercept_all();
        Some(iobitmap)
    }

    pub unsafe fn passthrough_all(&mut self) {
        self.a.clear_all();
        self.b.clear_all();
    }

    pub unsafe fn intercept_all(&mut self) {
        self.a.set_all();
        self.b.set_all();
    }

    pub unsafe fn intercept(&mut self, port: u16) {
        if port >= IOBitmap::RANGE_B {
            self.b.set_bit((port - IOBitmap::RANGE_B) as usize);
            return;
        }

        self.a.set_bit(port as usize);
    }

    pub unsafe fn passthrough(&mut self, port: u16) {
        if port >= IOBitmap::RANGE_B {
            self.b.clear_bit((port - IOBitmap::RANGE_B) as usize);
            return;
        }

        self.a.clear_bit(port as usize);
    }
}
