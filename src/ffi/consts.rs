#![allow(dead_code)]

use std::os::raw::c_int;

// libunwind error codes (libunwind-common.h, anonymous enum). Some are
// kept for use in error mapping or for future reference even when unused.
pub const UNW_ESUCCESS: c_int = 0;
pub const UNW_EUNSPEC: c_int = 1;
pub const UNW_ENOMEM: c_int = 2;
pub const UNW_EBADREG: c_int = 3;
pub const UNW_EREADONLYREG: c_int = 4;
pub const UNW_ESTOPUNWIND: c_int = 5;
pub const UNW_EINVALIDIP: c_int = 6;
pub const UNW_EBADFRAME: c_int = 7;
pub const UNW_EINVAL: c_int = 8;
pub const UNW_EBADVERSION: c_int = 9;
pub const UNW_ENOINFO: c_int = 10;

// Format constants (libunwind-dynamic.h enum). Order matches the enum.
pub const UNW_INFO_FORMAT_DYNAMIC: c_int = 0;
pub const UNW_INFO_FORMAT_TABLE: c_int = 1;
pub const UNW_INFO_FORMAT_REMOTE_TABLE: c_int = 2;
pub const UNW_INFO_FORMAT_ARM_EXIDX: c_int = 3;
pub const UNW_INFO_FORMAT_IP_OFFSET: c_int = 4;

// libunwind-common.h byteorder for unw_create_addr_space.
pub const UNW_LITTLE_ENDIAN: c_int = 1234;

// x86_64 register numbers (libunwind-x86_64.h enum).
#[cfg(target_arch = "x86_64")]
pub mod x86_64_regs {
    use std::os::raw::c_int;
    pub const UNW_X86_64_RAX: c_int = 0;
    pub const UNW_X86_64_RDX: c_int = 1;
    pub const UNW_X86_64_RCX: c_int = 2;
    pub const UNW_X86_64_RBX: c_int = 3;
    pub const UNW_X86_64_RSI: c_int = 4;
    pub const UNW_X86_64_RDI: c_int = 5;
    pub const UNW_X86_64_RBP: c_int = 6;
    pub const UNW_X86_64_RSP: c_int = 7;
    pub const UNW_X86_64_R8: c_int = 8;
    pub const UNW_X86_64_R9: c_int = 9;
    pub const UNW_X86_64_R10: c_int = 10;
    pub const UNW_X86_64_R11: c_int = 11;
    pub const UNW_X86_64_R12: c_int = 12;
    pub const UNW_X86_64_R13: c_int = 13;
    pub const UNW_X86_64_R14: c_int = 14;
    pub const UNW_X86_64_R15: c_int = 15;
    pub const UNW_X86_64_RIP: c_int = 16;
    pub const UNW_REG_IP: c_int = UNW_X86_64_RIP;
    pub const UNW_REG_SP: c_int = UNW_X86_64_RSP;
}

// aarch64 register numbers (libunwind-aarch64.h enum):
//   X0..X28 = 0..28, X29(FP)=29, X30(LR/IP)=30, SP=31, PC=32.
#[cfg(target_arch = "aarch64")]
pub mod aarch64_regs {
    use std::os::raw::c_int;
    pub const UNW_AARCH64_X29: c_int = 29; // FP
    pub const UNW_AARCH64_X30: c_int = 30; // LR
    pub const UNW_AARCH64_SP: c_int = 31;
    pub const UNW_AARCH64_PC: c_int = 32;
    pub const UNW_REG_IP: c_int = UNW_AARCH64_X30;
    pub const UNW_REG_SP: c_int = UNW_AARCH64_SP;
}
