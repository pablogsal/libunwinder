use libunwinder::{
    DwarfModuleSections, EhFrameHdrError, Error, ExplicitModuleSectionInfo, FrameAddress, Module,
    ModuleError, Unwinder,
};

#[test]
fn frame_address_adjusts_return_addresses_for_lookup() {
    let ip = FrameAddress::from_instruction_pointer(0x1000);
    assert_eq!(ip.address(), 0x1000);
    assert_eq!(ip.address_for_lookup(), 0x1000);
    assert!(!ip.is_return_address());

    let ra = FrameAddress::from_return_address(0x2000).unwrap();
    assert_eq!(ra.address(), 0x2000);
    assert_eq!(ra.address_for_lookup(), 0x1fff);
    assert!(ra.is_return_address());
    assert_eq!(FrameAddress::from_return_address(0), None);
}

#[test]
fn explicit_module_section_info_can_build_module_without_unwind_sections() {
    let module = Module::<Vec<u8>>::new(
        "empty".to_string(),
        0x1000..0x2000,
        0x1000,
        ExplicitModuleSectionInfo::default(),
    );

    assert_eq!(module.name(), "empty");
    assert_eq!(module.avma_range(), 0x1000..0x2000);
    assert_eq!(module.base_avma(), 0x1000);
}

#[test]
fn strict_dwarf_constructor_reports_missing_unwind_sections() {
    let err = Module::<Vec<u8>>::from_dwarf_sections(
        "empty".to_string(),
        0x1000..0x2000,
        0x1000,
        DwarfModuleSections::default(),
    )
    .err()
    .unwrap();

    assert_eq!(err, ModuleError::MissingEhFrameSvma);
}

#[test]
fn strict_dwarf_constructor_reports_malformed_eh_frame_hdr() {
    let err = Module::<Vec<u8>>::from_dwarf_sections(
        "bad".to_string(),
        0x1000..0x2000,
        0x1000,
        DwarfModuleSections {
            base_svma: 0,
            text_svma: Some(0..1),
            text: Some(vec![0]),
            eh_frame_svma: Some(0x100..0x101),
            eh_frame: Some(vec![0]),
            eh_frame_hdr_svma: Some(0x200..0x203),
            eh_frame_hdr: Some(vec![1, 0, 0]),
        },
    )
    .err()
    .unwrap();

    assert_eq!(
        err,
        ModuleError::InvalidEhFrameHdr(EhFrameHdrError::FixedHeaderTruncated { len: 3 })
    );
}

#[derive(Clone)]
struct SignalAwareDummyUnwinder;

impl Unwinder for SignalAwareDummyUnwinder {
    type UnwindRegs = ();
    type Cache = ();
    type Module = ();

    fn add_module(&mut self, _module: Self::Module) {}

    fn remove_module(&mut self, _avma_start: u64) {}

    fn max_known_code_address(&self) -> u64 {
        0
    }

    fn is_signal_frame(&self, frame: FrameAddress, _regs: &Self::UnwindRegs) -> bool {
        frame == FrameAddress::InstructionPointer(0x1000)
    }

    fn unwind_frame<F>(
        &self,
        _frame: FrameAddress,
        _regs: &mut Self::UnwindRegs,
        _cache: &mut Self::Cache,
        _read_stack: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        Ok(Some(0x2000))
    }
}

#[test]
fn iterator_preserves_signal_frame_instruction_pointer_semantics() {
    let unwinder = SignalAwareDummyUnwinder;
    let mut cache = ();
    let mut read_stack = |_addr| -> Result<u64, ()> { Err(()) };
    let mut iter = unwinder.iter_frames(0x1000, (), &mut cache, &mut read_stack);

    assert_eq!(
        iter.next(),
        Ok(Some(FrameAddress::InstructionPointer(0x1000)))
    );
    assert_eq!(
        iter.next(),
        Ok(Some(FrameAddress::InstructionPointer(0x2000)))
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn x86_64_register_api_tracks_optional_general_registers() {
    use libunwinder::x86_64::{Reg, UnwindRegsX86_64};

    let mut regs = UnwindRegsX86_64::new(0x10, 0x20, 0x30);
    assert_eq!(regs.ip(), 0x10);
    assert_eq!(regs.sp(), 0x20);
    assert_eq!(regs.bp(), 0x30);
    assert_eq!(regs.rip(), 0x10);
    assert_eq!(regs.rsp(), 0x20);
    assert_eq!(regs.rbp(), 0x30);

    assert_eq!(regs.get_if_set(Reg::R9), None);
    regs.set(Reg::R9, 0x90);
    assert_eq!(regs.get(Reg::R9), 0x90);
    assert_eq!(regs.get_if_set(Reg::R9), Some(0x90));

    regs.set_ip(0x11);
    regs.set_sp(0x22);
    regs.set_bp(0x33);
    assert_eq!((regs.ip(), regs.sp(), regs.bp()), (0x11, 0x22, 0x33));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn aarch64_pointer_auth_api_strips_configured_bits() {
    use libunwinder::aarch64::{PtrAuthMask, UnwindRegsAarch64};

    assert_eq!(PtrAuthMask::new_24_40().0, (1u64 << 40) - 1);
    assert_eq!(
        PtrAuthMask::from_max_known_address(0x0000_aaaa_b54f_7000).0,
        0x0000_ffff_ffff_ffff
    );

    let mask = PtrAuthMask(0x0000_ffff_ffff_ffff);
    let mut regs =
        UnwindRegsAarch64::new_with_ptr_auth_mask(mask, 0xabcd_0000_0000_1234, 0x20, 0x30);
    assert_eq!(regs.lr_mask(), mask);
    assert_eq!(regs.lr(), 0x1234);
    regs.set_lr(0xabcd_0000_0000_5678);
    regs.set_sp(0x40);
    regs.set_fp(0x50);
    assert_eq!((regs.lr(), regs.sp(), regs.fp()), (0x5678, 0x40, 0x50));
}
