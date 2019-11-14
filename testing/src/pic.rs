#[allow(dead_code)]

use x86_64::instructions::port::{PortRead, PortWrite};

use crate::interrupt_controller::InterruptController;
use crate::io::IO;

const MASTER_COMMAND: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_COMMAND: u16 = 0xa0;
const SLAVE_DATA: u16 = 0xa1;

const CMD_NEED_W4: u8 = 0x1;
const CMD_SINGLE: u8 = 0x2;
const CMD_INTERVAL4: u8 = 0x4;
const CMD_LEVEL: u8 = 0x8;
const CMD_INIT: u8 = 0x10;

const CMD_IRR: u8 = 0xa;
const CMD_ISR: u8 = 0xb;

const CMD_8086: u8 = 0x1;
const CMD_AUTO: u8 = 0x2;
const CMD_BUF_SLAVE: u8 = 0x8;
const CMD_BUF_MASTER: u8 = 0xc;
const CMD_SFNM: u8 = 0x10;

const MASTER_VECTOR_OFFSET: u8 = 0x20;
const SLAVE_VECTOR_OFFSET: u8 = 0x28;

pub struct PIC;

impl PIC {
    fn status(status: u8) -> u16 {
        unsafe {
            PortWrite::write_to_port(MASTER_COMMAND, status);
            PortWrite::write_to_port(SLAVE_COMMAND, status);

            let low: u8 = PortRead::read_from_port(MASTER_COMMAND);
            let high: u8 = PortRead::read_from_port(SLAVE_COMMAND);

            (low as u16) | ((high as u16) << 8)
        }
    }

    pub fn isr() -> u16 {
        PIC::status(CMD_ISR)
    }

    pub fn irr() -> u16 {
        PIC::status(CMD_IRR)
    }

    fn _reset(vector_offset: u8, master: bool) {
        let cmd: u16;
        let data: u16;
        let mask: u8;
        let wiring: u8;

        if master {
            cmd = MASTER_COMMAND;
            data = MASTER_DATA;
            wiring = 0x4;
        } else {
            cmd = SLAVE_COMMAND;
            data = SLAVE_DATA;
            wiring = 0x2;
        }

        unsafe {
            mask = PortRead::read_from_port(data);
            PortWrite::write_to_port(cmd, CMD_INIT | CMD_NEED_W4);
            IO::wait();
            PortWrite::write_to_port(data, vector_offset);
            IO::wait();
            PortWrite::write_to_port(data, wiring);
            IO::wait();
            PortWrite::write_to_port(data, CMD_8086);
            IO::wait();
            PortWrite::write_to_port(data, mask);
            IO::wait();
        }
    }
}

impl InterruptController for PIC {
    fn enable() {}

    fn disable() {
        unsafe {
            PortWrite::write_to_port(MASTER_DATA as u16, 0xff as u8);
            PortWrite::write_to_port(SLAVE_DATA as u16, 0xff as u8);
        }
    }

    fn reset() {
        PIC::_reset(MASTER_VECTOR_OFFSET, true);
        PIC::_reset(SLAVE_VECTOR_OFFSET, false);
    }

    fn eoi(irq: u32) {
        unsafe {
            if irq > 8 {
                PortWrite::write_to_port(SLAVE_COMMAND, 0x20 as u8);
            }

            PortWrite::write_to_port(MASTER_COMMAND, 0x20 as u8);
        }
    }

    fn spurious_irq() -> u32 {
        0
    }

    fn mask(irq: u32) {
        let data: u16;
        let mask: u8;

        if irq > 8 {
            data = SLAVE_DATA;
            mask = 1 << ((irq as u8) - 8);
        } else {
            data = MASTER_DATA;
            mask = 1 << (irq as u8);
        }

        unsafe {
            let value: u8 = PortRead::read_from_port(data);
            PortWrite::write_to_port(data as u16, mask | value);
        }
    }

    fn unmask(irq: u32) {
        let data: u16;
        let mask: u8;

        if irq > 8 {
            data = SLAVE_DATA;
            mask = 1 << ((irq as u8) - 8);
        } else {
            data = MASTER_DATA;
            mask = 1 << (irq as u8);
        }

        unsafe {
            let value: u8 = PortRead::read_from_port(data);
            PortWrite::write_to_port(data as u16, !mask & value);
        }
    }
}