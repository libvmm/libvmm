use super::vmcs::*;

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

pub enum TSExitSource {
    CALL,
    IRET,
    JMP,
    IDT,
}

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
