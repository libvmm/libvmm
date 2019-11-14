use x86_64::instructions::port::PortWrite;

pub struct IO;

impl IO {
    pub fn wait() {
        unsafe { PortWrite::write_to_port(0x80, 0x0 as u8) }
    }
}