use core::fmt;
use core::fmt::Write;

pub struct Writer;

impl Writer {
    pub fn write_string(&mut self, s: &str) {
        for byte in s.bytes() {
            unsafe {
                x86_64::instructions::port::PortWrite::write_to_port(0x3f8, byte as u8);
            }
        }
    }
}

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::output::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    Writer.write_fmt(args).unwrap();
}
