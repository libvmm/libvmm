use super::bitmap::Bitmap;
use crate::{AlignedAddress, KiB, SHIFT_4K};

pub enum MSRPassthroughMode {
    READ,
    WRITE,
    RW,
    None,
}

pub struct MSRBitmap {
    read_low: Bitmap,
    read_high: Bitmap,
    write_low: Bitmap,
    write_high: Bitmap,
}

impl MSRBitmap {
    const RANGE_HIGH: u32 = 0xc0000000;

    pub unsafe fn new_raw(address: u64) -> Option<Self> {
        if !address.aligned(SHIFT_4K) {
            return None;
        }

        let mut bitmap = MSRBitmap {
            read_low: Bitmap::new_raw(address, KiB).unwrap(),
            read_high: Bitmap::new_raw(address + KiB as u64, KiB).unwrap(),
            write_low: Bitmap::new_raw(address + 2 * KiB as u64, KiB).unwrap(),
            write_high: Bitmap::new_raw(address + 3 * KiB as u64, KiB).unwrap(),
        };

        bitmap.intercept_all();
        Some(bitmap)
    }

    pub unsafe fn passthrough_all(&mut self) {
        self.read_low.clear_all();
        self.read_high.clear_all();
        self.write_low.clear_all();
        self.write_high.clear_all();
    }

    pub unsafe fn intercept_all(&mut self) {
        self.read_low.set_all();
        self.read_high.set_all();
        self.write_low.set_all();
        self.write_high.set_all();
    }

    pub unsafe fn passthrough(&mut self, msr: u32, mode: MSRPassthroughMode) {
        let mut read = false;
        let mut write = false;

        match mode {
            MSRPassthroughMode::RW => {
                read = true;
                write = true;
            }
            MSRPassthroughMode::READ => {
                read = true;
            }
            MSRPassthroughMode::WRITE => {
                write = true;
            }
            MSRPassthroughMode::None => (),
        }

        /* Make sure everything is intercepted first */
        if msr >= MSRBitmap::RANGE_HIGH {
            self.read_high
                .set_bit((msr - MSRBitmap::RANGE_HIGH) as usize);
            self.write_high
                .set_bit((msr - MSRBitmap::RANGE_HIGH) as usize);
        } else {
            self.read_low.set_bit(msr as usize);
            self.write_low.set_bit(msr as usize);
        }

        if read {
            if msr >= MSRBitmap::RANGE_HIGH {
                self.read_high
                    .clear_bit((msr - MSRBitmap::RANGE_HIGH) as usize);
            } else {
                self.read_low.clear_bit(msr as usize);
            }
        }

        if write {
            if msr >= MSRBitmap::RANGE_HIGH {
                self.write_high
                    .clear_bit((msr - MSRBitmap::RANGE_HIGH) as usize);
            } else {
                self.write_low.clear_bit(msr as usize);
            }
        }
    }
}
