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
