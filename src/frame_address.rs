use std::num::NonZeroU64;

/// An absolute code address for a stack frame.
///
/// The initial frame is an instruction pointer, while frames recovered by
/// unwinding are return addresses and need a one-byte lookup adjustment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameAddress {
    InstructionPointer(u64),
    ReturnAddress(NonZeroU64),
}

impl FrameAddress {
    #[must_use]
    pub fn from_instruction_pointer(ip: u64) -> Self {
        FrameAddress::InstructionPointer(ip)
    }

    /// Wrap a return address recovered from `unwind_frame`. Returns `None`
    /// if the return address is zero.
    #[must_use]
    pub fn from_return_address(ra: u64) -> Option<Self> {
        NonZeroU64::new(ra).map(FrameAddress::ReturnAddress)
    }

    /// The address used for module / unwind-info lookup. For a return
    /// address we step back one byte so the lookup lands inside the
    /// `call` instruction rather than past it.
    #[must_use]
    pub fn address_for_lookup(&self) -> u64 {
        match *self {
            FrameAddress::InstructionPointer(ip) => ip,
            FrameAddress::ReturnAddress(ra) => u64::from(ra) - 1,
        }
    }

    /// The raw address, without the return-address lookup adjustment.
    #[must_use]
    pub fn address(&self) -> u64 {
        match *self {
            FrameAddress::InstructionPointer(a) => a,
            FrameAddress::ReturnAddress(a) => a.into(),
        }
    }

    #[must_use]
    pub fn is_return_address(&self) -> bool {
        matches!(self, FrameAddress::ReturnAddress(_))
    }

    /// Compatibility alias for callers that use the older raw-address name.
    #[must_use]
    pub fn raw_address(&self) -> u64 {
        self.address()
    }
}
