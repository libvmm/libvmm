use crate::x86_64::instructions::vmcs::*;

pub enum IntType {
    ExternalInterrupt = 0,
    NMI = 2,
    HardwareException = 3,
    SoftwareInterrupt = 4,
    PrivilegedException = 5,
    SoftwareException = 6,
    Other = 7,
}

pub fn inject_event(vector: u8, int_type: IntType) {
    let interruption_info = vector as u32 | ((int_type as u32) << 8) | (1 << 31);

    VMCSField32Control::VM_ENTRY_INTR_INFO_FIELD.write(interruption_info);
}

pub fn inject_event_with_error(vector: u8, int_type: IntType, error_code: u32, len: u32) {
    let interruption_info = vector as u32 | ((int_type as u32) << 8) | (1 << 11) | (1 << 31);

    VMCSField32Control::VM_ENTRY_INTR_INFO_FIELD.write(interruption_info);
    VMCSField32Control::VM_ENTRY_EXCEPTION_ERROR_CODE.write(error_code);
    VMCSField32Control::VM_ENTRY_INSTRUCTION_LEN.write(len);
}