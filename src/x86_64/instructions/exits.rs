use super::vmcs::*;

#[derive(Debug, Copy, Clone)]
pub enum VMXExitReason {
    EXCEPTION_NMI = 0,
    EXTERNAL_INTERRUPT = 1,
    TRIPLE_FAULT = 2,
    PENDING_INTERRUPT = 7,
    NMI_WINDOW = 8,
    TASK_SWITCH = 9,
    CPUID = 10,
    HLT = 12,
    INVD = 13,
    INVLPG = 14,
    RDPMC = 15,
    RDTSC = 16,
    VMCALL = 18,
    VMCLEAR = 19,
    VMLAUNCH = 20,
    VMPTRLD = 21,
    VMPTRST = 22,
    VMREAD = 23,
    VMRESUME = 24,
    VMWRITE = 25,
    VMOFF = 26,
    VMON = 27,
    CR_ACCESS = 28,
    DR_ACCESS = 29,
    IO_INSTRUCTION = 30,
    MSR_READ = 31,
    MSR_WRITE = 32,
    INVALID_STATE = 33,
    MSR_LOAD_FAIL = 34,
    MWAIT_INSTRUCTION = 36,
    MONITOR_TRAP_FLAG = 37,
    MONITOR_INSTRUCTION = 39,
    PAUSE_INSTRUCTION = 40,
    MCE_DURING_VMENTRY = 41,
    TPR_BELOW_THRESHOLD = 43,
    APIC_ACCESS = 44,
    EOI_INDUCED = 45,
    GDTR_IDTR = 46,
    LDTR_TR = 47,
    EPT_VIOLATION = 48,
    EPT_MISCONFIG = 49,
    INVEPT = 50,
    RDTSCP = 51,
    PREEMPTION_TIMER = 52,
    INVVPID = 53,
    WBINVD = 54,
    XSETBV = 55,
    APIC_WRITE = 56,
    RDRAND = 57,
    INVPCID = 58,
    VMFUNC = 59,
    ENCLS = 60,
    RDSEED = 61,
    PML_FULL = 62,
    XSAVES = 63,
    XRSTORS = 64,
}

#[derive(Debug)]
pub struct DebugExceptionExit {
    pub exit_qual: u64,
}

impl DebugExceptionExit {
    pub fn new() -> Self {
        Self {
            exit_qual: VMCSField64ReadOnly::EXIT_QUALIFICATION.read(),
        }
    }

    pub fn is_b(&self, index: usize) -> bool {
        debug_assert!(index < 4);
        ((self.exit_qual >> index) & 1) == 1
    }

    pub fn is_bd(&self) -> bool {
        ((self.exit_qual >> 13) & 1) == 1
    }

    pub fn is_bs(&self) -> bool {
        ((self.exit_qual >> 14) & 1) == 1
    }
}

#[derive(Debug)]
pub enum TSExitSource {
    CALL,
    IRET,
    JMP,
    IDT,
}

#[derive(Debug)]
pub struct TSExit {
    pub exit_qual: u64,
}

impl TSExit {
    pub fn new() -> Self {
        Self {
            exit_qual: VMCSField64ReadOnly::EXIT_QUALIFICATION.read(),
        }
    }

    pub fn selector(&self) -> u16 {
        self.exit_qual as u16
    }

    pub fn source(&self) -> TSExitSource {
        match (self.exit_qual >> 30) & 0x3 {
            0 => TSExitSource::CALL,
            1 => TSExitSource::IRET,
            2 => TSExitSource::JMP,
            3 => TSExitSource::IDT,
            _ => panic!("Invalid"),
        }
    }
}

#[derive(Debug)]
pub enum CRAccessType {
    MovToCR,
    MovFromCR,
    CLTS,
    LMSW,
}

#[derive(Debug)]
pub struct CRAccessExit {
    pub exit_qual: u64,
}

impl CRAccessExit {
    pub fn new() -> Self {
        Self {
            exit_qual: VMCSField64ReadOnly::EXIT_QUALIFICATION.read(),
        }
    }

    pub fn cr(&self) -> usize {
        (self.exit_qual & 0xf) as usize
    }

    pub fn access_type(&self) -> CRAccessType {
        match (self.exit_qual >> 4) & 0x3 {
            0 => CRAccessType::MovToCR,
            1 => CRAccessType::MovFromCR,
            2 => CRAccessType::CLTS,
            3 => CRAccessType::LMSW,
            _ => panic!("Invalid"),
        }
    }

    pub fn is_lmsw_register(&self) -> bool {
        ((self.exit_qual >> 6) & 1) == 0
    }

    pub fn reg(&self) -> usize {
        ((self.exit_qual >> 8) & 0xf) as usize
    }

    pub fn lmsw_source(&self) -> usize {
        ((self.exit_qual >> 16) & 0xff) as usize
    }
}

#[derive(Debug)]
pub struct MovDRExit {
    pub exit_qual: u64,
}

impl MovDRExit {
    pub fn new() -> Self {
        Self {
            exit_qual: VMCSField64ReadOnly::EXIT_QUALIFICATION.read(),
        }
    }

    pub fn debug_register(&self) -> usize {
        (self.exit_qual & 0x3) as usize
    }

    pub fn is_to_dr(&self) -> bool {
        ((self.exit_qual >> 4) & 0x1) == 0
    }

    pub fn register(&self) -> usize {
        ((self.exit_qual >> 8) & 0xf) as usize
    }
}

#[derive(Debug)]
pub struct IOExit {
    pub exit_qual: u64,
}

impl IOExit {
    pub fn new() -> Self {
        Self {
            exit_qual: VMCSField64ReadOnly::EXIT_QUALIFICATION.read(),
        }
    }

    pub fn size(&self) -> usize {
        match self.exit_qual & 0x7 {
            0 => 1,
            1 => 2,
            3 => 4,
            _ => panic!("Invalid"),
        }
    }

    pub fn is_out(&self) -> bool {
        ((self.exit_qual >> 3) & 0x1) == 0
    }

    pub fn is_string(&self) -> bool {
        ((self.exit_qual >> 4) & 0x1) == 1
    }

    pub fn is_rep(&self) -> bool {
        ((self.exit_qual >> 5) & 0x1) == 1
    }

    pub fn is_op_immediate(&self) -> bool {
        ((self.exit_qual >> 6) & 0x1) == 1
    }

    pub fn port(&self) -> u16 {
        (self.exit_qual >> 16) as u16
    }
}

#[derive(Debug)]
pub enum ApicAccessType {
    LinearDataRead,
    LinearDataWrite,
    LinearInstructionFetch,
    LinearEvent,
    GuestEvent,
    GuestInstruction,
}

#[derive(Debug)]
pub struct ApicAccessExit {
    pub exit_qual: u64,
    pub guest_linear_address: u64,
}

impl ApicAccessExit {
    pub fn new() -> Self {
        Self {
            exit_qual: VMCSField64ReadOnly::EXIT_QUALIFICATION.read(),
            guest_linear_address: VMCSField64ReadOnly::GUEST_LINEAR_ADDRESS.read(),
        }
    }

    pub fn offset(&self) -> usize {
        (self.exit_qual & 0xfff) as usize
    }

    pub fn access_type(&self) -> ApicAccessType {
        match (self.exit_qual >> 12) & 0xf {
            0 => ApicAccessType::LinearDataRead,
            1 => ApicAccessType::LinearDataWrite,
            2 => ApicAccessType::LinearInstructionFetch,
            3 => ApicAccessType::LinearEvent,
            10 => ApicAccessType::GuestEvent,
            15 => ApicAccessType::GuestInstruction,
            _ => panic!("Invalid"),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum EPTViolationType {
    DataRead,
    DataWrite,
    InstructionFetch,
}

#[derive(Debug)]
pub struct EPTViolationExit {
    pub exit_qual: u64,
    pub guest_physical_address: u64,
}

impl EPTViolationExit {
    pub fn new() -> Self {
        Self {
            exit_qual: VMCSField64ReadOnly::EXIT_QUALIFICATION.read(),
            guest_physical_address: VMCSField64ReadOnly::GUEST_PHYSICAL_ADDRESS.read(),
        }
    }

    pub fn violation_type(&self) -> EPTViolationType {
        match self.exit_qual & 0x7 {
            1 => EPTViolationType::DataRead,
            2 => EPTViolationType::DataWrite,
            4 => EPTViolationType::InstructionFetch,
            _ => panic!("Invalid"),
        }
    }

    pub fn is_reable(&self) -> bool {
        ((self.exit_qual >> 3) & 0x1) == 1
    }

    pub fn is_writable(&self) -> bool {
        ((self.exit_qual >> 4) & 0x1) == 1
    }

    pub fn is_executable(&self) -> bool {
        ((self.exit_qual >> 5) & 0x1) == 1
    }

    pub fn is_user_executable(&self) -> bool {
        ((self.exit_qual >> 6) & 0x1) == 1
    }

    pub fn is_valid(&self) -> bool {
        ((self.exit_qual >> 7) & 0x1) == 1
    }

    pub fn is_pagetable(&self) -> bool {
        ((self.exit_qual >> 8) & 0x1) == 1
    }

    pub fn is_supervisor(&self) -> bool {
        ((self.exit_qual >> 9) & 0x1) == 0
    }

    pub fn is_nmi(&self) -> bool {
        ((self.exit_qual >> 12) & 0x1) == 1
    }
}