#[derive(Debug)]
pub struct EmulationContext {
    lock: bool,
    repne: bool,
    rep: bool,
    bound: bool,
    mode: Mode,
    cs_override: bool,
    ss_override: bool,
    ds_override: bool,
    es_override: bool,
    fs_override: bool,
    gs_override: bool,
    branch_taken: bool,
    branch_not_taken: bool,
    operand_size_override: bool,
    address_size_override: bool,
    next: State,
    registers: Registers,
}

impl EmulationContext {
    pub fn new() -> Self {
        EmulationContext {
            lock: false,
            repne: false,
            rep: false,
            bound: false,
            mode: Mode::REAL,
            cs_override: false,
            ss_override: false,
            ds_override: false,
            es_override: false,
            fs_override: false,
            gs_override: false,
            branch_taken: false,
            branch_not_taken: false,
            operand_size_override: false,
            address_size_override: false,
            next: State::Prefix,
            registers: Default::default(),
        }
    }

    pub fn address_size(&self) -> u8 {
        // todo@ account for prefixes as well
        self.mode.address_size()
    }

    pub fn failed(&self) -> bool {
        self.next == State::Fail
    }

    pub fn fail(&mut self) {
        self.next = State::Fail;
    }

    fn reg_index(&self, register: usize) -> usize {
        let longmode = self.mode == Mode::PROT64;
        let rex_b = false;

        (register & 0x7) |
            ((rex_b as usize) << 3) |
            ((longmode as usize) << 4)
    }

    pub fn register_read8(&self, index: usize, word: u8) -> u8 {
        self.registers.read8(self.reg_index(index), word)
    }

    pub fn register_read16(&self, index: usize, word: u8) -> u16 {
        self.registers.read16(self.reg_index(index), word)
    }

    pub fn register_read32(&self, index: usize, word: u8) -> u32 {
        self.registers.read32(self.reg_index(index), word)
    }

    pub fn register_read64(&self, index: usize) -> u64 {
        self.registers.read64(self.reg_index(index))
    }

    pub fn register_write8(&mut self, index: usize, value: u8, word: u8) {
        self.registers.write8(self.reg_index(index), value, word);
    }

    pub fn register_write16(&mut self, index: usize, value: u16, word: u8) {
        self.registers.write16(self.reg_index(index), value, word);
    }

    pub fn register_write32(&mut self, index: usize, value: u32, word: u8) {
        self.registers.write32(self.reg_index(index), value, word);
    }

    pub fn register_write64(&mut self, index: usize, value: u64) {
        self.registers.write64(self.reg_index(index), value);
    }
}

#[derive(Debug, Eq, PartialEq)]
enum State {
    Prefix,
    OpCode,
    MOD,
    Displacement,
    Immediate,
    Fail,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum Mode {
    REAL,
    VM86,
    PROT16,
    PROT32,
    PROT64,
}

impl Mode {
    pub fn address_size(&self) -> u8 {
        match self {
            Mode::REAL | Mode::VM86 | Mode::PROT16 => 2,
            Mode::PROT32 => 32,
            Mode::PROT64 => 64,
        }
    }
}

struct ModRM(u8);

impl ModRM {
    pub fn MOD(&self) -> u8 {
        self.0 >> 6
    }

    pub fn RM(&self) -> u8 {
        (self.0 >> 3) & 0x7
    }

    pub fn REG(&self) -> u8 {
        self.0 & 0x7
    }
}

#[derive(Debug, Default)]
struct Registers {
    reg: [u64; 32],
}

impl Registers {
    fn read8(&self, index: usize, offset: u8) -> u8 {
        ((self.reg[index] >> offset) & 0xff) as u8
    }

    fn read16(&self, index: usize, offset: u8) -> u16 {
        ((self.reg[index] >> offset) & 0xffff) as u16
    }

    fn read32(&self, index: usize, offset: u8) -> u32 {
        ((self.reg[index] >> offset) & 0xffffffff) as u32
    }

    fn read64(&self, index: usize) -> u64 {
        self.reg[index]
    }

    fn write8(&mut self, index: usize, value: u8, word: u8) {
        let offset = word * 8;
        let mask = !(((1 as u64) << offset) - 1);
        let result = (value as u64) << offset;
        self.reg[index] = (self.reg[index] & mask) | result;
    }

    fn write16(&mut self, index: usize, value: u16, word: u8) {
        let offset = word * 16;
        let mask = !(((1 as u64) << offset) - 1);
        let result = (value as u64) << offset;
        self.reg[index] = (self.reg[index] & mask) | result;
    }

    fn write32(&mut self, index: usize, value: u32, word: u8) {
        let offset = word * 32;
        let mask = !(((1 as u64)<< offset) - 1);
        let result = (value as u64) << offset;
        self.reg[index] = (self.reg[index] & mask) | result;
    }

    fn write64(&mut self, index: usize, value: u64) {
        self.reg[index] = value;
    }
}

pub struct ByteStream {
    offset: usize,
    size: usize,
    ptr: *mut u8,
}

impl ByteStream {
    pub fn new(addr: u64, size: usize) -> Self {
        ByteStream {
            offset: 0,
            size: size,
            ptr: addr as *mut u8,
        }
    }

    pub fn next(&mut self) -> Option<u8> {
        if self.offset >= self.size {
            return None;
        }

        let addr = (self.ptr as usize + self.offset);
        let val = unsafe { *(addr as *mut u8) };
        self.offset += 1;

        Some(val)
    }

    pub fn peek(&mut self) -> Option<u8> {
        if self.offset >= self.size {
            return None;
        }

        Some(unsafe { *((self.ptr as usize + self.offset) as *mut u8) })
    }
}

//
// Parses the prefix including mandatory opcode prefix and escape
//
// ## 2. opcode (2.1.2 Opcodes):
//
// -> 1 byte opcodes:
//
// * opcode1
//
// -> 2 byte opcodes:
//
// * 0x0F (escape) + opcode1
// * 0x66/0xF2/0xF3 (mandatory prefix) + 0x0F (escape) + opcode1
//
// -> 3 byte opcodes:
//
// * 0x0F (escape) + opcode1 + opcode2
// * 0x66/0xF2/0xF3 (mandatory prefix) + 0x0F (escape) + opcode1 + opcode2
//
fn parse_prefix(stream: &mut ByteStream, context: &mut EmulationContext) {
    let instruction = match stream.peek().clone() {
        Some(ins) => ins.clone(),
        None => {
            context.fail();
            return;
        },
    };

    // 2.1.1 Instruction prefix
    match instruction {
        // Escape
        0x0F => {
            stream.next();
        },

        // Segment override
        0x2E => {
            context.cs_override = true;
            stream.next();
        },
        0x36 => {
            context.ss_override = true;
            stream.next();
        },
        0x3E => {
            context.ds_override = true;
            stream.next();
        },
        0x26 => {
            context.es_override = true;
            stream.next();
        },
        0x64 => {
            context.fs_override = true;
            stream.next();
        },
        0x65 => {
            context.gs_override = true;
            stream.next();
        },

        // Branch hints
        0x2E => {
            context.branch_taken = true;
            stream.next();
        },
        0x3E => {
            context.branch_not_taken = true;
            stream.next();
        },

        // Operand size override
        0x66 => {
            stream.next();
            match stream.peek() {
                Some(0x0F) => { stream.next(); }
                _ => context.operand_size_override = true,
            }
        },

        // Address size override
        0x67 => {
            context.address_size_override = true;
            stream.next();
        },

        // Lock
        0xF0 => {
            context.lock = true;
            stream.next();
        },

        0xF2 | 0xF3 => {
            stream.next();

            match stream.peek() {
                // Escape
                Some(0x0F) => { stream.next(); },
                // Repeat
                _ => {
                    if instruction == 0xF2 {
                        context.repne = true;

                        // Bound prefix:
                        // 1- CPUID.(EAX=07H, ECX=0):EBX.MPX[bit 14]
                        // 2- BNDCFGU.EN and/or IA32_BNDCFGS.EN is set
                        // 3- When the F2 prefix precedes:
                        //    a) near CALL
                        //    b) near RET
                        //    c) near JMP
                        //    d) near Jcc instruction
                        context.bound = true;
                    }

                    if instruction == 0xF3 {
                        context.rep = true;
                    }
                },
            }
        },

        _ => (),
    }

    context.next = State::OpCode;
}

pub fn decode_instruction(input: &mut ByteStream, context: &mut EmulationContext) {
    // # Protected Mode
    //
    // ## 3. ModR/M (2.1.3 ModR/M and SIB Bytes)
    //
    // ## 4. SIB
    //
    // ## 5. Displacement
    //
    // ## 6. Immediate Data

    parse_prefix(input, context);

    if context.failed() {
        return;
    }

    let instruction = match input.next() {
        Some(ins) => ins,
        None => {
            context.fail();
            return;
        },
    };

    match instruction {
        // xor %r16, %r16
        // xor %r32, %r32
        0x31 => {
            let modrm = match input.next() {
                Some(val) => ModRM(val),
                None => {
                    context.fail();
                    return;
                }
            };
            let (dst, src) = (modrm.RM() as usize, modrm.REG() as usize);

            if context.address_size() == 2 {
                let result = context.register_read16(src, 0) ^ context.register_read16(dst, 0);
                context.register_write16(dst, result, 0);
            } else {
                let result = context.register_read32(src, 0) ^ context.register_read32(dst, 0);
                context.register_write32(dst, result, 0);
            }
        },
        // mov r/m16, r16
        // mov r/m32, r32
        0x89 => {
            let modrm = match input.next() {
                Some(val) => ModRM(val),
                None => {
                    context.fail();
                    return;
                }
            };
            let (dst, src) = (modrm.RM() as usize, modrm.REG() as usize);

            if context.address_size() == 2 {
                let result = context.register_read16(src, 0);
                context.register_write16(dst, result, 0);
            } else {
                let result = context.register_read32(src, 0);
                context.register_write32(dst, result, 0);
            }
        },
        // mov r8, imm8
        0xb0 ... 0xb7 => {
            let reg_index = (instruction & 0x7) as usize;
            let imm8 = match input.next() {
                Some(val) => val,
                None => {
                    context.fail();
                    return;
                }
            };

            context.register_write8(reg_index, imm8, 0);
        },
        // outb $imm, %al
        0xe6 => {
            let imm8 = match input.next() {
                Some(val) => val,
                None => {
                    context.fail();
                    return;
                }
            };

            // todo handle this outside
        },
        // hlt
        0xf4 => (),
        _ => {
            println!("[FAIL ] unknown opcode: 0x{:x}", instruction);
            context.fail();
        },
    }

    return;
}

/*

use lazy_static::lazy_static;

fn operand_size(rex: bool, mode: Mode) -> u8 {
    mode as u8
}

#[derive(Debug, Copy, Clone)]
struct Instruction {
    name: &'static str,
    valid: bool,
    flags: OpCode,
}

#[derive(Debug)]
enum Operand {
    NONE,
    SReg,

    M8,
    M16,
    M32,
    M64,

    R8,
    R16,
    R32,
    R64,

    RM8,
    RM16,
    RM32,
    RM64,

    MOffs8,
    MOffs16,
    MOffs32,
    MOffs64,

    Al,
    Ax,
    Eax,
    Rax,

    Imm8,
    Imm16,
    Imm32,
    Imm64,
}

bitflags! {
    pub struct OpCode: u32 {
        const NONE  = 0 << 0;
        const R8    = 1 << 0;
        const R     = 1 << 1;
        const I8    = 1 << 2;
        const I     = 1 << 3;
    }
}

static InvalidOneByteOpcode: Instruction = Instruction {
    name: "unknown", valid: false, flags: OpCode::NONE
};

lazy_static! {
    static ref ONEBYTE_OPCODES: [Instruction; 256] = [
    /* 0x00 */ InvalidOneByteOpcode,
    /* 0x01 */ InvalidOneByteOpcode,
    /* 0x02 */ InvalidOneByteOpcode,
    /* 0x03 */ InvalidOneByteOpcode,
    /* 0x04 */ InvalidOneByteOpcode,
    /* 0x05 */ InvalidOneByteOpcode,
    /* 0x06 */ InvalidOneByteOpcode,
    /* 0x07 */ InvalidOneByteOpcode,
    /* 0x08 */ InvalidOneByteOpcode,
    /* 0x09 */ InvalidOneByteOpcode,
    /* 0x0A */ InvalidOneByteOpcode,
    /* 0x0B */ InvalidOneByteOpcode,
    /* 0x0C */ InvalidOneByteOpcode,
    /* 0x0D */ InvalidOneByteOpcode,
    /* 0x0E */ InvalidOneByteOpcode,
    /* 0x0F */ InvalidOneByteOpcode,


    /* 0x10 */ InvalidOneByteOpcode,
    /* 0x11 */ InvalidOneByteOpcode,
    /* 0x12 */ InvalidOneByteOpcode,
    /* 0x13 */ InvalidOneByteOpcode,
    /* 0x14 */ InvalidOneByteOpcode,
    /* 0x15 */ InvalidOneByteOpcode,
    /* 0x16 */ InvalidOneByteOpcode,
    /* 0x17 */ InvalidOneByteOpcode,
    /* 0x18 */ InvalidOneByteOpcode,
    /* 0x19 */ InvalidOneByteOpcode,
    /* 0x1A */ InvalidOneByteOpcode,
    /* 0x1B */ InvalidOneByteOpcode,
    /* 0x1C */ InvalidOneByteOpcode,
    /* 0x1D */ InvalidOneByteOpcode,
    /* 0x1E */ InvalidOneByteOpcode,
    /* 0x1F */ InvalidOneByteOpcode,

    /* 0x20 */ InvalidOneByteOpcode,
    /* 0x21 */ InvalidOneByteOpcode,
    /* 0x22 */ InvalidOneByteOpcode,
    /* 0x23 */ InvalidOneByteOpcode,
    /* 0x24 */ InvalidOneByteOpcode,
    /* 0x25 */ InvalidOneByteOpcode,
    /* 0x26 */ InvalidOneByteOpcode,
    /* 0x27 */ InvalidOneByteOpcode,
    /* 0x28 */ InvalidOneByteOpcode,
    /* 0x29 */ InvalidOneByteOpcode,
    /* 0x2A */ InvalidOneByteOpcode,
    /* 0x2B */ InvalidOneByteOpcode,
    /* 0x2C */ InvalidOneByteOpcode,
    /* 0x2D */ InvalidOneByteOpcode,
    /* 0x2E */ InvalidOneByteOpcode,
    /* 0x2F */ InvalidOneByteOpcode,

    /* 0x30 */ InvalidOneByteOpcode,
    /* 0x31 */ InvalidOneByteOpcode,
    /* 0x32 */ InvalidOneByteOpcode,
    /* 0x33 */ InvalidOneByteOpcode,
    /* 0x34 */ InvalidOneByteOpcode,
    /* 0x35 */ InvalidOneByteOpcode,
    /* 0x36 */ InvalidOneByteOpcode,
    /* 0x37 */ InvalidOneByteOpcode,
    /* 0x38 */ InvalidOneByteOpcode,
    /* 0x39 */ InvalidOneByteOpcode,
    /* 0x3A */ InvalidOneByteOpcode,
    /* 0x3B */ InvalidOneByteOpcode,
    /* 0x3C */ InvalidOneByteOpcode,
    /* 0x3D */ InvalidOneByteOpcode,
    /* 0x3E */ InvalidOneByteOpcode,
    /* 0x3F */ InvalidOneByteOpcode,

    /* 0x40 */ InvalidOneByteOpcode,
    /* 0x41 */ InvalidOneByteOpcode,
    /* 0x42 */ InvalidOneByteOpcode,
    /* 0x43 */ InvalidOneByteOpcode,
    /* 0x44 */ InvalidOneByteOpcode,
    /* 0x45 */ InvalidOneByteOpcode,
    /* 0x46 */ InvalidOneByteOpcode,
    /* 0x47 */ InvalidOneByteOpcode,
    /* 0x48 */ InvalidOneByteOpcode,
    /* 0x49 */ InvalidOneByteOpcode,
    /* 0x4A */ InvalidOneByteOpcode,
    /* 0x4B */ InvalidOneByteOpcode,
    /* 0x4C */ InvalidOneByteOpcode,
    /* 0x4D */ InvalidOneByteOpcode,
    /* 0x4E */ InvalidOneByteOpcode,
    /* 0x4F */ InvalidOneByteOpcode,

    /* 0x50 */ InvalidOneByteOpcode,
    /* 0x51 */ InvalidOneByteOpcode,
    /* 0x52 */ InvalidOneByteOpcode,
    /* 0x53 */ InvalidOneByteOpcode,
    /* 0x54 */ InvalidOneByteOpcode,
    /* 0x55 */ InvalidOneByteOpcode,
    /* 0x56 */ InvalidOneByteOpcode,
    /* 0x57 */ InvalidOneByteOpcode,
    /* 0x58 */ InvalidOneByteOpcode,
    /* 0x59 */ InvalidOneByteOpcode,
    /* 0x5A */ InvalidOneByteOpcode,
    /* 0x5B */ InvalidOneByteOpcode,
    /* 0x5C */ InvalidOneByteOpcode,
    /* 0x5D */ InvalidOneByteOpcode,
    /* 0x5E */ InvalidOneByteOpcode,
    /* 0x5F */ InvalidOneByteOpcode,

    /* 0x60 */ InvalidOneByteOpcode,
    /* 0x61 */ InvalidOneByteOpcode,
    /* 0x62 */ InvalidOneByteOpcode,
    /* 0x63 */ InvalidOneByteOpcode,
    /* 0x64 */ InvalidOneByteOpcode,
    /* 0x65 */ InvalidOneByteOpcode,
    /* 0x66 */ InvalidOneByteOpcode,
    /* 0x67 */ InvalidOneByteOpcode,
    /* 0x68 */ InvalidOneByteOpcode,
    /* 0x69 */ InvalidOneByteOpcode,
    /* 0x6A */ InvalidOneByteOpcode,
    /* 0x6B */ InvalidOneByteOpcode,
    /* 0x6C */ InvalidOneByteOpcode,
    /* 0x6D */ InvalidOneByteOpcode,
    /* 0x6E */ InvalidOneByteOpcode,
    /* 0x6F */ InvalidOneByteOpcode,

    /* 0x70 */ InvalidOneByteOpcode,
    /* 0x71 */ InvalidOneByteOpcode,
    /* 0x72 */ InvalidOneByteOpcode,
    /* 0x73 */ InvalidOneByteOpcode,
    /* 0x74 */ InvalidOneByteOpcode,
    /* 0x75 */ InvalidOneByteOpcode,
    /* 0x76 */ InvalidOneByteOpcode,
    /* 0x77 */ InvalidOneByteOpcode,
    /* 0x78 */ InvalidOneByteOpcode,
    /* 0x79 */ InvalidOneByteOpcode,
    /* 0x7A */ InvalidOneByteOpcode,
    /* 0x7B */ InvalidOneByteOpcode,
    /* 0x7C */ InvalidOneByteOpcode,
    /* 0x7D */ InvalidOneByteOpcode,
    /* 0x7E */ InvalidOneByteOpcode,
    /* 0x7F */ InvalidOneByteOpcode,

    /* 0x80 */ InvalidOneByteOpcode,
    /* 0x81 */ InvalidOneByteOpcode,
    /* 0x82 */ InvalidOneByteOpcode,
    /* 0x83 */ InvalidOneByteOpcode,
    /* 0x84 */ InvalidOneByteOpcode,
    /* 0x85 */ InvalidOneByteOpcode,
    /* 0x86 */ InvalidOneByteOpcode,
    /* 0x87 */ InvalidOneByteOpcode,
    /* 0x88 */ Instruction { name: "mov", valid: true, flags: OpCode::NONE  },
    /* 0x89 */ Instruction { name: "mov", valid: true, flags: OpCode::NONE  },
    /* 0x8A */ Instruction { name: "mov", valid: true, flags: OpCode::NONE  },
    /* 0x8B */ Instruction { name: "mov", valid: true, flags: OpCode::NONE  },
    /* 0x8C */ Instruction { name: "mov", valid: true, flags: OpCode::NONE  },
    /* 0x8D */ InvalidOneByteOpcode,
    /* 0x8E */ Instruction { name: "mov", valid: true, flags: OpCode::NONE  },
    /* 0x8F */ InvalidOneByteOpcode,

    /* 0x90 */ InvalidOneByteOpcode,
    /* 0x91 */ InvalidOneByteOpcode,
    /* 0x92 */ InvalidOneByteOpcode,
    /* 0x93 */ InvalidOneByteOpcode,
    /* 0x94 */ InvalidOneByteOpcode,
    /* 0x95 */ InvalidOneByteOpcode,
    /* 0x96 */ InvalidOneByteOpcode,
    /* 0x97 */ InvalidOneByteOpcode,
    /* 0x98 */ InvalidOneByteOpcode,
    /* 0x99 */ InvalidOneByteOpcode,
    /* 0x9A */ InvalidOneByteOpcode,
    /* 0x9B */ InvalidOneByteOpcode,
    /* 0x9C */ InvalidOneByteOpcode,
    /* 0x9D */ InvalidOneByteOpcode,
    /* 0x9E */ InvalidOneByteOpcode,
    /* 0x9F */ InvalidOneByteOpcode,


    /* 0xA0 */ Instruction { name: "mov", valid: true, flags: OpCode::NONE  },
    /* 0xA1 */ Instruction { name: "mov", valid: true, flags: OpCode::NONE  },
    /* 0xA2 */ Instruction { name: "mov", valid: true, flags: OpCode::NONE  },
    /* 0xA3 */ Instruction { name: "mov", valid: true, flags: OpCode::NONE  },
    /* 0xA4 */ InvalidOneByteOpcode,
    /* 0xA5 */ InvalidOneByteOpcode,
    /* 0xA6 */ InvalidOneByteOpcode,
    /* 0xA7 */ InvalidOneByteOpcode,
    /* 0xA8 */ InvalidOneByteOpcode,
    /* 0xA9 */ InvalidOneByteOpcode,
    /* 0xAA */ InvalidOneByteOpcode,
    /* 0xAB */ InvalidOneByteOpcode,
    /* 0xAC */ InvalidOneByteOpcode,
    /* 0xAD */ InvalidOneByteOpcode,
    /* 0xAE */ InvalidOneByteOpcode,
    /* 0xAF */ InvalidOneByteOpcode,

    /* 0xB0 */ Instruction { name: "mov", valid: true, flags: OpCode::R8 | OpCode::I8 },
    /* 0xB1 */ Instruction { name: "mov", valid: true, flags: OpCode::R8 | OpCode::I8 },
    /* 0xB2 */ Instruction { name: "mov", valid: true, flags: OpCode::R8 | OpCode::I8 },
    /* 0xB3 */ Instruction { name: "mov", valid: true, flags: OpCode::R8 | OpCode::I8 },
    /* 0xB4 */ Instruction { name: "mov", valid: true, flags: OpCode::R8 | OpCode::I8 },
    /* 0xB5 */ Instruction { name: "mov", valid: true, flags: OpCode::R8 | OpCode::I8 },
    /* 0xB6 */ Instruction { name: "mov", valid: true, flags: OpCode::R8 | OpCode::I8 },
    /* 0xB7 */ Instruction { name: "mov", valid: true, flags: OpCode::R8 | OpCode::I8 },

    /* 0xB8 */ Instruction { name: "mov", valid: true, flags: OpCode::R | OpCode::I },
    /* 0xB9 */ Instruction { name: "mov", valid: true, flags: OpCode::R | OpCode::I },
    /* 0xBA */ Instruction { name: "mov", valid: true, flags: OpCode::R | OpCode::I },
    /* 0xBB */ Instruction { name: "mov", valid: true, flags: OpCode::R | OpCode::I },
    /* 0xBC */ Instruction { name: "mov", valid: true, flags: OpCode::R | OpCode::I },
    /* 0xBD */ Instruction { name: "mov", valid: true, flags: OpCode::R | OpCode::I },
    /* 0xBE */ Instruction { name: "mov", valid: true, flags: OpCode::R | OpCode::I },
    /* 0xBF */ Instruction { name: "mov", valid: true, flags: OpCode::R | OpCode::I },

    /* 0xC0 */ InvalidOneByteOpcode,
    /* 0xC1 */ InvalidOneByteOpcode,
    /* 0xC2 */ InvalidOneByteOpcode,
    /* 0xC3 */ InvalidOneByteOpcode,
    /* 0xC4 */ InvalidOneByteOpcode,
    /* 0xC5 */ InvalidOneByteOpcode,
    /* 0xC6 */ Instruction { name: "mov", valid: true, flags: OpCode::NONE  },
    /* 0xC7 */ Instruction { name: "mov", valid: true, flags: OpCode::NONE  },
    /* 0xC8 */ InvalidOneByteOpcode,
    /* 0xC9 */ InvalidOneByteOpcode,
    /* 0xCA */ InvalidOneByteOpcode,
    /* 0xCB */ InvalidOneByteOpcode,
    /* 0xCC */ InvalidOneByteOpcode,
    /* 0xCD */ InvalidOneByteOpcode,
    /* 0xCE */ InvalidOneByteOpcode,
    /* 0xCF */ InvalidOneByteOpcode,

    /* 0xD0 */ InvalidOneByteOpcode,
    /* 0xD1 */ InvalidOneByteOpcode,
    /* 0xD2 */ InvalidOneByteOpcode,
    /* 0xD3 */ InvalidOneByteOpcode,
    /* 0xD4 */ InvalidOneByteOpcode,
    /* 0xD5 */ InvalidOneByteOpcode,
    /* 0xD6 */ InvalidOneByteOpcode,
    /* 0xD7 */ InvalidOneByteOpcode,
    /* 0xD8 */ InvalidOneByteOpcode,
    /* 0xD9 */ InvalidOneByteOpcode,
    /* 0xDA */ InvalidOneByteOpcode,
    /* 0xDB */ InvalidOneByteOpcode,
    /* 0xDC */ InvalidOneByteOpcode,
    /* 0xDD */ InvalidOneByteOpcode,
    /* 0xDE */ InvalidOneByteOpcode,
    /* 0xDF */ InvalidOneByteOpcode,

    /* 0xE0 */ InvalidOneByteOpcode,
    /* 0xE1 */ InvalidOneByteOpcode,
    /* 0xE2 */ InvalidOneByteOpcode,
    /* 0xE3 */ InvalidOneByteOpcode,
    /* 0xE4 */ InvalidOneByteOpcode,
    /* 0xE5 */ InvalidOneByteOpcode,
    /* 0xE6 */ Instruction { name: "out", valid: true, flags: OpCode::R | OpCode::I8 },
    /* 0xE7 */ Instruction { name: "out", valid: true, flags: OpCode::NONE },
    /* 0xE8 */ InvalidOneByteOpcode,
    /* 0xE9 */ InvalidOneByteOpcode,
    /* 0xEA */ InvalidOneByteOpcode,
    /* 0xEB */ InvalidOneByteOpcode,
    /* 0xEC */ InvalidOneByteOpcode,
    /* 0xED */ InvalidOneByteOpcode,
    /* 0xEE */ Instruction { name: "out", valid: true, flags: OpCode::NONE },
    /* 0xEF */ Instruction { name: "out", valid: true, flags: OpCode::NONE },

    /* 0xF0 */ InvalidOneByteOpcode,
    /* 0xF1 */ InvalidOneByteOpcode,
    /* 0xF2 */ InvalidOneByteOpcode,
    /* 0xF3 */ InvalidOneByteOpcode,
    /* 0xF4 */ Instruction { name: "hlt", valid: true, flags: OpCode::NONE },
    /* 0xF5 */ InvalidOneByteOpcode,
    /* 0xF6 */ InvalidOneByteOpcode,
    /* 0xF7 */ InvalidOneByteOpcode,
    /* 0xF8 */ InvalidOneByteOpcode,
    /* 0xF9 */ InvalidOneByteOpcode,
    /* 0xFA */ InvalidOneByteOpcode,
    /* 0xFB */ InvalidOneByteOpcode,
    /* 0xFC */ InvalidOneByteOpcode,
    /* 0xFD */ InvalidOneByteOpcode,
    /* 0xFE */ InvalidOneByteOpcode,
    /* 0xFF */ InvalidOneByteOpcode,
];
}

pub fn emulate_generic() {
    let ins = &ONEBYTE_OPCODES[instruction as usize];

    if ! ins.valid {
        context.fail();
        return;
    }

    let current_size = if ins.flags.contains(OpCode::I8) {
        1
    } else {
        operand_size(false, Mode::Real)
    };


    let rindex = if ins.flags.contains(OpCode::R8) || ins.flags.contains(OpCode::R) {
        register_index(instruction & 0x7, false, false)
    } else {
        0xff
    };

    let imm = if ins.flags.contains(OpCode::I8) || ins.flags.contains(OpCode::I) {
        let mut value: u64 = 0;

        for index in 0..current_size {
            match input.next() {
                Some(entry) => value |= (entry << index) as u64,
                None => {
                    context.fail();
                    return;
                },
            }
        }

        value
    } else {
        0
    };
}

*/