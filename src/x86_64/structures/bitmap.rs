use crate::AlignedAddress;

pub struct Bitmap {
    pub size: usize,
    array: *mut u64,
}

impl Bitmap {
    pub fn new_raw(address: u64, size: usize) -> Option<Self> {
        if !(size as u64).aligned(3) {
            return None;
        }

        Some(Bitmap {
            size: size,
            array: address as *mut u64,
        })
    }

    pub unsafe fn set_all(&mut self) {
        for index in 0..self.size {
            *((self.array as u64 + index as u64) as *mut u64) = 0xffffffff_ffffffff;
        }
    }

    pub unsafe fn clear_all(&mut self) {
        for index in 0..self.size {
            *((self.array as u64 + index as u64) as *mut u64) = 0x00;
        }
    }

    pub unsafe fn set_bit(&mut self, offset: usize) {
        let index = offset >> 6;
        let bit: u64 = (offset & 0x3f) as u64;

        *((self.array as u64 + index as u64) as *mut u64) |= 1 << bit;
    }

    pub unsafe fn clear_bit(&mut self, offset: usize) {
        let index = offset >> 6;
        let bit: u64 = (offset & 0x3f) as u64;

        *((self.array as u64 + index as u64) as *mut u64) =
            *((self.array as u64 + index as u64) as *mut u64) & !(1 << bit);
    }
}
