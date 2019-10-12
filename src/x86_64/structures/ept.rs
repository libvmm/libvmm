use bitflags::bitflags;
use libvmm_macros::construct_pt_types;
use crate::{SHIFT_1G, SHIFT_2M, SHIFT_4K, SHIFT_512G, unsafe_cast};

bitflags! {
    pub struct EPTPFlags: u64 {
        const MT_UNCACHEABLE =  0x0 << 0;
        const MT_WRITEBACK =    0x3 << 1;
        const PT_WALK_LENGTH =  0x7 << 3;
        const AD =              0x1 << 6;
    }
}

bitflags! {
    pub struct EPTEntryFlags: u64 {
        const READABLE =                1 << 0;
        const WRITABLE =                1 << 1;
        const SUPERVISOR_EXECUTABLE =   1 << 2;
        const EPT_MT =                  7 << 3;
        const IGNORE_PAT =              1 << 6;
        const HUGE =                    1 << 7;
        const ACCESSED =                1 << 8;
        const DIRTY =                   1 << 9;
        const USER_EXECUTABLE =         1 << 10;
        const SUPRESS_VE =              1 << 63;
    }
}

/// VMCS EPT Pointer
pub struct EPTPointer(u64);

impl EPTPointer {
    pub fn new(address: u64, flags: EPTPFlags) -> Option<Self> {
        if  (address & ((1 << SHIFT_4K) - 1)) != 0 {
            return None;
        }

        Some(Self(address | flags.bits() | (3 << 3)))
    }

    pub fn raw(&self) -> u64 {
        self.0
    }
}

/// 4 KiB
construct_pt_types! {
    pub struct EPTPT {
        valid_flags: (EPTEntryFlags::READABLE |
                      EPTEntryFlags::WRITABLE |
                      EPTEntryFlags::SUPERVISOR_EXECUTABLE |
                      EPTEntryFlags::USER_EXECUTABLE |
                      EPTEntryFlags::EPT_MT).bits(),
        valid_huge_flags: 0x0,
        huge_flags: 0x0,
        normal_shift: SHIFT_4K,
        huge_shift: 0,
        index_shift: SHIFT_4K,
    }
}

/// 2 MiB
construct_pt_types! {
    pub struct EPTPD {
        valid_flags: (EPTEntryFlags::READABLE |
                      EPTEntryFlags::WRITABLE |
                      EPTEntryFlags::SUPERVISOR_EXECUTABLE |
                      EPTEntryFlags::USER_EXECUTABLE).bits(),
        valid_huge_flags: (EPTEntryFlags::HUGE |
                           EPTEntryFlags::EPT_MT |
                           EPTEntryFlags::IGNORE_PAT).bits(),
        huge_flags: EPTEntryFlags::HUGE.bits(),
        normal_shift: SHIFT_4K,
        huge_shift: SHIFT_2M,
        index_shift: SHIFT_2M,
    }
}

/// 1 GiB
construct_pt_types! {
    pub struct EPTPDP {
        valid_flags: (EPTEntryFlags::READABLE |
                      EPTEntryFlags::WRITABLE |
                      EPTEntryFlags::SUPERVISOR_EXECUTABLE |
                      EPTEntryFlags::USER_EXECUTABLE).bits(),
        valid_huge_flags: (EPTEntryFlags::HUGE |
                           EPTEntryFlags::EPT_MT |
                           EPTEntryFlags::IGNORE_PAT).bits(),
        huge_flags: EPTEntryFlags::HUGE.bits(),
        normal_shift: SHIFT_4K,
        huge_shift: SHIFT_1G,
        index_shift: SHIFT_1G,
    }
}

/// 512 GiB
construct_pt_types! {
    pub struct EPTPML4 {
        valid_flags: (EPTEntryFlags::READABLE |
                      EPTEntryFlags::WRITABLE |
                      EPTEntryFlags::SUPERVISOR_EXECUTABLE |
                      EPTEntryFlags::USER_EXECUTABLE).bits(),
        valid_huge_flags: 0x0,
        huge_flags: 0x0,
        normal_shift: SHIFT_4K,
        huge_shift: 0,
        index_shift: SHIFT_512G,
    }
}

#[macro_export]
macro_rules! ept_pml4_table {
    ($x:expr) => {
        unsafe_cast!($x => &mut EPTPML4)
    }
}

#[macro_export]
macro_rules! ept_pdp_table {
    ($x:expr) => {
        unsafe_cast!($x => &mut EPTPDP)
    }
}

#[macro_export]
macro_rules! ept_pd_table {
    ($x:expr) => {
        unsafe_cast!($x => &mut EPTPD)
    }
}

#[macro_export]
macro_rules! ept_page_table {
    ($x:expr) => {
        unsafe_cast!($x => &mut EPTPT)
    }
}