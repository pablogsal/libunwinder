use std::collections::BTreeMap;
use std::fs::File;
use std::marker::PhantomData;
use std::ops::{Deref, Range};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::eh_frame_table::{EhFrameHdrError, EhFrameTable};
use crate::error::Error;
use crate::ffi::DwarfCieInfo;
use crate::frame_address::FrameAddress;
use memmap2::{Mmap, MmapOptions};
use object::{Object, ObjectSection};

/// Interface for providing module section ranges and bytes.
///
/// Each data method is called at most once for a given name, so implementors
/// may move owned buffers out of their backing storage.
pub trait ModuleSectionInfo<D> {
    fn base_svma(&self) -> u64;
    fn section_svma_range(&mut self, name: &[u8]) -> Option<Range<u64>>;
    fn section_data(&mut self, name: &[u8]) -> Option<D>;

    fn segment_svma_range(&mut self, _name: &[u8]) -> Option<Range<u64>> {
        None
    }

    fn segment_data(&mut self, _name: &[u8]) -> Option<D> {
        None
    }
}

/// DWARF unwind section information for a loaded module.
///
/// Field names describe SVMAs and section bytes using conventional object-file
/// terminology so loaders can fill this struct directly.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DwarfModuleSections<S> {
    pub base_svma: u64,
    pub text_svma: Option<Range<u64>>,
    pub text: Option<S>,
    pub eh_frame_svma: Option<Range<u64>>,
    pub eh_frame: Option<S>,
    pub eh_frame_hdr_svma: Option<Range<u64>>,
    pub eh_frame_hdr: Option<S>,
}

/// Explicit object section data used by [`Module::new`].
///
/// This struct intentionally accepts a superset of the Linux DWARF sections
/// libunwinder currently consumes. Unsupported fields are ignored, which keeps
/// backend adapters simple when they already collect a broader object-section
/// bag.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExplicitModuleSectionInfo<S> {
    pub base_svma: u64,
    pub text_svma: Option<Range<u64>>,
    pub text: Option<S>,
    pub stubs_svma: Option<Range<u64>>,
    pub stub_helper_svma: Option<Range<u64>>,
    pub got_svma: Option<Range<u64>>,
    pub unwind_info: Option<S>,
    pub eh_frame_svma: Option<Range<u64>>,
    pub eh_frame: Option<S>,
    pub eh_frame_hdr_svma: Option<Range<u64>>,
    pub eh_frame_hdr: Option<S>,
    pub debug_frame: Option<S>,
    pub text_segment_svma: Option<Range<u64>>,
    pub text_segment: Option<S>,
}

/// A byte slice backed by a shared read-only memory map.
///
/// Cloning this type is cheap: clones share the same mmap and carry a different
/// byte range. It is intended for large object files where copying
/// `.eh_frame` / `.eh_frame_hdr` sections would be expensive.
#[derive(Clone)]
pub struct MmapBytes {
    mmap: Arc<Mmap>,
    range: Range<usize>,
}

impl MmapBytes {
    /// Build a mapped byte view from an existing mmap and byte range.
    #[must_use]
    pub fn new(mmap: Arc<Mmap>, range: Range<usize>) -> Option<Self> {
        if range.start <= range.end && range.end <= mmap.len() {
            Some(Self { mmap, range })
        } else {
            None
        }
    }

    fn from_file_range(mmap: Arc<Mmap>, offset: u64, size: u64) -> Option<Self> {
        let start = usize::try_from(offset).ok()?;
        let len = usize::try_from(size).ok()?;
        let end = start.checked_add(len)?;
        Self::new(mmap, start..end)
    }
}

impl std::fmt::Debug for MmapBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmapBytes")
            .field("range", &self.range)
            .field("len", &self.len())
            .finish()
    }
}

impl Deref for MmapBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.mmap[self.range.clone()]
    }
}

/// Errors returned by mmap-backed module loading.
#[derive(Debug)]
pub enum MmapModuleError {
    Open {
        path: PathBuf,
        source: std::io::Error,
    },
    Map {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: object::Error,
    },
    Module(ModuleError),
}

impl std::fmt::Display for MmapModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open { path, source } => {
                write!(f, "failed to open {}: {source}", path.display())
            }
            Self::Map { path, source } => {
                write!(f, "failed to mmap {}: {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(
                    f,
                    "failed to parse {} as an object file: {source}",
                    path.display()
                )
            }
            Self::Module(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for MmapModuleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Map { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::Module(err) => Some(err),
        }
    }
}

impl<S> ModuleSectionInfo<S> for DwarfModuleSections<S>
where
    S: Deref<Target = [u8]>,
{
    fn base_svma(&self) -> u64 {
        self.base_svma
    }

    fn section_svma_range(&mut self, name: &[u8]) -> Option<Range<u64>> {
        match name {
            b"__text" | b".text" => self.text_svma.clone(),
            b"__eh_frame" | b".eh_frame" => self.eh_frame_svma.clone(),
            b"__eh_frame_hdr" | b".eh_frame_hdr" => self.eh_frame_hdr_svma.clone(),
            _ => None,
        }
    }

    fn section_data(&mut self, name: &[u8]) -> Option<S> {
        match name {
            b"__text" | b".text" => self.text.take(),
            b"__eh_frame" | b".eh_frame" => self.eh_frame.take(),
            b"__eh_frame_hdr" | b".eh_frame_hdr" => self.eh_frame_hdr.take(),
            _ => None,
        }
    }
}

impl<S> ModuleSectionInfo<S> for ExplicitModuleSectionInfo<S>
where
    S: Deref<Target = [u8]>,
{
    fn base_svma(&self) -> u64 {
        self.base_svma
    }

    fn section_svma_range(&mut self, name: &[u8]) -> Option<Range<u64>> {
        match name {
            b"__text" | b".text" => self.text_svma.clone(),
            b"__stubs" => self.stubs_svma.clone(),
            b"__stub_helper" => self.stub_helper_svma.clone(),
            b"__got" | b".got" => self.got_svma.clone(),
            b"__eh_frame" | b".eh_frame" => self.eh_frame_svma.clone(),
            b"__eh_frame_hdr" | b".eh_frame_hdr" => self.eh_frame_hdr_svma.clone(),
            _ => None,
        }
    }

    fn section_data(&mut self, name: &[u8]) -> Option<S> {
        match name {
            b"__text" | b".text" => self.text.take(),
            b"__unwind_info" => self.unwind_info.take(),
            b"__eh_frame" | b".eh_frame" => self.eh_frame.take(),
            b"__eh_frame_hdr" | b".eh_frame_hdr" => self.eh_frame_hdr.take(),
            b"__debug_frame" | b".debug_frame" => self.debug_frame.take(),
            _ => None,
        }
    }

    fn segment_svma_range(&mut self, name: &[u8]) -> Option<Range<u64>> {
        match name {
            b"__TEXT" => self.text_segment_svma.clone(),
            _ => None,
        }
    }

    fn segment_data(&mut self, name: &[u8]) -> Option<S> {
        match name {
            b"__TEXT" => self.text_segment.take(),
            _ => None,
        }
    }
}

struct MmapObjectSections<'data> {
    file: object::File<'data, &'data [u8]>,
    mmap: Arc<Mmap>,
}

impl ModuleSectionInfo<MmapBytes> for MmapObjectSections<'_> {
    fn base_svma(&self) -> u64 {
        self.file.relative_address_base()
    }

    fn section_svma_range(&mut self, name: &[u8]) -> Option<Range<u64>> {
        let section = self.file.section_by_name_bytes(name)?;
        Some(section.address()..section.address().saturating_add(section.size()))
    }

    fn section_data(&mut self, name: &[u8]) -> Option<MmapBytes> {
        let section = self.file.section_by_name_bytes(name)?;
        let (offset, size) = section.file_range()?;
        MmapBytes::from_file_range(Arc::clone(&self.mmap), offset, size)
    }
}

/// Errors returned when constructing a module with DWARF unwind info.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleError {
    EmptyAvmaRange,
    MissingEhFrame,
    MissingEhFrameSvma,
    MissingEhFrameHdr,
    MissingEhFrameHdrSvma,
    InvalidEhFrameHdr(EhFrameHdrError),
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyAvmaRange => f.write_str("module AVMA range is empty"),
            Self::MissingEhFrame => f.write_str("module is missing .eh_frame bytes"),
            Self::MissingEhFrameSvma => f.write_str("module is missing .eh_frame SVMA range"),
            Self::MissingEhFrameHdr => f.write_str("module is missing .eh_frame_hdr bytes"),
            Self::MissingEhFrameHdrSvma => {
                f.write_str("module is missing .eh_frame_hdr SVMA range")
            }
            Self::InvalidEhFrameHdr(err) => write!(f, "invalid .eh_frame_hdr: {err}"),
        }
    }
}

impl std::error::Error for ModuleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEhFrameHdr(err) => Some(err),
            _ => None,
        }
    }
}

/// A section whose bytes we mirror locally so libunwind's `access_mem` can
/// short-circuit per-byte tracee reads.
pub(crate) struct LocalSection {
    pub avma_start: u64,
    pub avma_end: u64,
    pub local_ptr: *const u8,
}

// SAFETY: `local_ptr` points into section bytes kept alive by `ModuleData::_sections`.
unsafe impl Send for LocalSection {}
// SAFETY: see `Send` impl above; reads through `local_ptr` are read-only.
unsafe impl Sync for LocalSection {}

pub(crate) struct FunctionDetails {
    pub start_ip: u64,
    pub end_ip: u64,
    pub cie_info: DwarfCieInfo,
    pub lsda: u64,
    pub handler: u64,
    pub signal_frame: bool,
}

trait SectionBytes: Send + Sync {
    fn bytes(&self) -> &[u8];
}

impl<S> SectionBytes for S
where
    S: Deref<Target = [u8]> + Send + Sync + 'static,
{
    fn bytes(&self) -> &[u8] {
        self.deref()
    }
}

type OwnedSection = Box<dyn SectionBytes>;

struct OwnedModuleSections {
    _eh_frame_hdr: Option<OwnedSection>,
    _eh_frame: Option<OwnedSection>,
}

pub(crate) struct ModuleData {
    pub name: String,
    pub avma_range: Range<u64>,
    pub base_avma: u64,
    pub local_sections: Vec<LocalSection>,
    pub table: EhFrameTable,
    pub eh_frame_hdr_local_ptr: *const u8,
    pub eh_frame_hdr_local_len: usize,
    pub eh_frame_local_ptr: *const u8,
    pub eh_frame_local_len: usize,
    pub eh_frame_avma: u64,
    pub eh_frame_hdr_error: Option<EhFrameHdrError>,
    pub function_cache: Mutex<BTreeMap<u64, Arc<FunctionDetails>>>,
    pub text_base: u64,
    pub data_base: u64,
    _sections: OwnedModuleSections,
}

// SAFETY: local pointers are read-only and kept alive by `_sections`.
unsafe impl Send for ModuleData {}
// SAFETY: see `Send` impl above; reads are read-only and shareable.
unsafe impl Sync for ModuleData {}

/// Module metadata and unwind sections for one loaded image range.
pub struct Module<S> {
    pub(crate) data: Arc<ModuleData>,
    _phantom: PhantomData<fn() -> S>,
}

impl<S> Clone for Module<S> {
    fn clone(&self) -> Self {
        Self {
            data: Arc::clone(&self.data),
            _phantom: PhantomData,
        }
    }
}

impl<S> Module<S>
where
    S: Deref<Target = [u8]> + Send + Sync + 'static,
{
    /// Build a module from object-section data.
    ///
    /// Missing unwind sections are accepted and produce a module that will use
    /// frame-pointer fallback for its address range. Use
    /// [`Module::try_from_section_info`] or [`Module::from_dwarf_sections`] when
    /// missing unwind data should be treated as a construction error.
    #[must_use]
    pub fn new(
        name: String,
        avma_range: Range<u64>,
        base_avma: u64,
        section_info: impl ModuleSectionInfo<S>,
    ) -> Self {
        Self::from_parts(module_parts_from_section_info(
            name,
            avma_range,
            base_avma,
            section_info,
        ))
    }

    /// Build a module from typed DWARF unwind sections.
    pub fn from_dwarf_sections(
        name: String,
        avma_range: Range<u64>,
        base_avma: u64,
        sections: DwarfModuleSections<S>,
    ) -> Result<Self, ModuleError> {
        let parts = ModuleParts {
            name,
            avma_range,
            base_avma,
            base_svma: sections.base_svma,
            text_svma: sections.text_svma,
            eh_frame_svma: sections.eh_frame_svma,
            eh_frame: sections.eh_frame,
            eh_frame_hdr_svma: sections.eh_frame_hdr_svma,
            eh_frame_hdr: sections.eh_frame_hdr,
        };
        validate_module_parts(&parts)?;
        Ok(Self::from_parts(parts))
    }

    /// Build a module from an adapter while requiring complete DWARF unwind
    /// sections.
    pub fn try_from_section_info(
        name: String,
        avma_range: Range<u64>,
        base_avma: u64,
        section_info: impl ModuleSectionInfo<S>,
    ) -> Result<Self, ModuleError> {
        let parts = module_parts_from_section_info(name, avma_range, base_avma, section_info);
        validate_module_parts(&parts)?;
        Ok(Self::from_parts(parts))
    }

    #[must_use]
    pub fn fallback_only(name: String, avma_range: Range<u64>, base_avma: u64) -> Self {
        Self::from_parts(ModuleParts {
            name,
            avma_range,
            base_avma,
            base_svma: base_avma,
            text_svma: None,
            eh_frame_svma: None,
            eh_frame: None,
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
        })
    }

    #[must_use]
    pub fn avma_range(&self) -> Range<u64> {
        self.data.avma_range.clone()
    }

    #[must_use]
    pub fn base_avma(&self) -> u64 {
        self.data.base_avma
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.data.name
    }
}

impl Module<MmapBytes> {
    /// Build a module from a read-only mmap of an object file.
    ///
    /// Object parsing still uses the `object` crate, but unwind sections are
    /// stored as mmap-backed byte ranges instead of copied into heap buffers.
    /// Missing or unsupported unwind sections follow [`Module::new`] semantics:
    /// the module is still created and can use frame-pointer fallback.
    pub fn from_mmap_file(
        path: impl AsRef<Path>,
        avma_range: Range<u64>,
        base_avma: u64,
    ) -> Result<Self, MmapModuleError> {
        let path = path.as_ref();
        let mmap = mmap_file(path)?;
        let file = object::File::parse(&mmap[..]).map_err(|source| MmapModuleError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self::new(
            path.to_string_lossy().into_owned(),
            avma_range,
            base_avma,
            MmapObjectSections {
                file,
                mmap: Arc::clone(&mmap),
            },
        ))
    }

    /// Build a module from a read-only mmap while requiring complete DWARF
    /// unwind sections.
    pub fn try_from_mmap_file(
        path: impl AsRef<Path>,
        avma_range: Range<u64>,
        base_avma: u64,
    ) -> Result<Self, MmapModuleError> {
        let path = path.as_ref();
        let mmap = mmap_file(path)?;
        let file = object::File::parse(&mmap[..]).map_err(|source| MmapModuleError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        Self::try_from_section_info(
            path.to_string_lossy().into_owned(),
            avma_range,
            base_avma,
            MmapObjectSections {
                file,
                mmap: Arc::clone(&mmap),
            },
        )
        .map_err(MmapModuleError::Module)
    }
}

fn mmap_file(path: &Path) -> Result<Arc<Mmap>, MmapModuleError> {
    let file = File::open(path).map_err(|source| MmapModuleError::Open {
        path: path.to_path_buf(),
        source,
    })?;
    // SAFETY: the map is read-only and the crate never mutates the file through
    // this handle. External file mutation has the normal OS mmap semantics.
    let mmap = unsafe { MmapOptions::new().map(&file) }.map_err(|source| MmapModuleError::Map {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(Arc::new(mmap))
}

struct ModuleParts<S> {
    name: String,
    avma_range: Range<u64>,
    base_avma: u64,
    base_svma: u64,
    text_svma: Option<Range<u64>>,
    eh_frame_svma: Option<Range<u64>>,
    eh_frame: Option<S>,
    eh_frame_hdr_svma: Option<Range<u64>>,
    eh_frame_hdr: Option<S>,
}

impl<S> Module<S>
where
    S: Deref<Target = [u8]> + Send + Sync + 'static,
{
    fn from_parts(parts: ModuleParts<S>) -> Self {
        let ModuleParts {
            name,
            avma_range,
            base_avma,
            base_svma,
            text_svma,
            eh_frame_svma,
            eh_frame,
            eh_frame_hdr_svma,
            eh_frame_hdr,
        } = parts;

        let slide = base_avma.wrapping_sub(base_svma);
        let mut local_sections = Vec::with_capacity(2);
        let eh_frame_hdr = eh_frame_hdr.map(|bytes| Box::new(bytes) as OwnedSection);
        let eh_frame = eh_frame.map(|bytes| Box::new(bytes) as OwnedSection);

        let (
            table,
            eh_frame_hdr_local_ptr,
            eh_frame_hdr_local_len,
            eh_frame_hdr_avma,
            eh_frame_hdr_error,
        ) = match (&eh_frame_hdr, &eh_frame_hdr_svma) {
            (Some(section), Some(svma)) => {
                let bytes = section.bytes();
                let avma = svma.start.wrapping_add(slide);
                local_sections.push(LocalSection {
                    avma_start: avma,
                    avma_end: avma.saturating_add(bytes.len() as u64),
                    local_ptr: bytes.as_ptr(),
                });
                let (table, eh_frame_hdr_error) = match EhFrameTable::parse(
                    bytes,
                    svma.start,
                    eh_frame_svma.as_ref().map(|r| r.start),
                    base_avma,
                    base_svma,
                    avma_range.start,
                    avma,
                ) {
                    Ok(table) => (table, None),
                    Err(err) => (EhFrameTable::empty(avma), Some(err)),
                };
                (table, bytes.as_ptr(), bytes.len(), avma, eh_frame_hdr_error)
            }
            _ => (EhFrameTable::empty(0), std::ptr::null(), 0, 0, None),
        };

        let (eh_frame_local_ptr, eh_frame_local_len, eh_frame_avma) =
            match (&eh_frame, &eh_frame_svma) {
                (Some(section), Some(svma)) => {
                    let bytes = section.bytes();
                    let avma = svma.start.wrapping_add(slide);
                    local_sections.push(LocalSection {
                        avma_start: avma,
                        avma_end: avma.saturating_add(bytes.len() as u64),
                        local_ptr: bytes.as_ptr(),
                    });
                    (bytes.as_ptr(), bytes.len(), avma)
                }
                _ => (std::ptr::null(), 0, 0),
            };

        let text_base = text_svma
            .as_ref()
            .map_or(avma_range.start, |r| r.start.wrapping_add(slide));

        Self {
            data: Arc::new(ModuleData {
                name,
                avma_range,
                base_avma,
                local_sections,
                table,
                eh_frame_hdr_local_ptr,
                eh_frame_hdr_local_len,
                eh_frame_local_ptr,
                eh_frame_local_len,
                eh_frame_avma,
                eh_frame_hdr_error,
                function_cache: Mutex::new(BTreeMap::new()),
                text_base,
                data_base: eh_frame_hdr_avma,
                _sections: OwnedModuleSections {
                    _eh_frame_hdr: eh_frame_hdr,
                    _eh_frame: eh_frame,
                },
            }),
            _phantom: PhantomData,
        }
    }
}

fn section_range<S>(
    section_info: &mut impl ModuleSectionInfo<S>,
    primary: &[u8],
    alternate: &[u8],
) -> Option<Range<u64>> {
    section_info
        .section_svma_range(primary)
        .or_else(|| section_info.section_svma_range(alternate))
}

fn section_data<S>(
    section_info: &mut impl ModuleSectionInfo<S>,
    primary: &[u8],
    alternate: &[u8],
) -> Option<S> {
    section_info
        .section_data(primary)
        .or_else(|| section_info.section_data(alternate))
}

fn module_parts_from_section_info<S>(
    name: String,
    avma_range: Range<u64>,
    base_avma: u64,
    mut section_info: impl ModuleSectionInfo<S>,
) -> ModuleParts<S> {
    ModuleParts {
        name,
        avma_range,
        base_avma,
        base_svma: section_info.base_svma(),
        text_svma: section_range(&mut section_info, b".text", b"__text"),
        eh_frame_svma: section_range(&mut section_info, b".eh_frame", b"__eh_frame"),
        eh_frame: section_data(&mut section_info, b".eh_frame", b"__eh_frame"),
        eh_frame_hdr_svma: section_range(&mut section_info, b".eh_frame_hdr", b"__eh_frame_hdr"),
        eh_frame_hdr: section_data(&mut section_info, b".eh_frame_hdr", b"__eh_frame_hdr"),
    }
}

fn validate_module_parts<S>(parts: &ModuleParts<S>) -> Result<(), ModuleError>
where
    S: Deref<Target = [u8]>,
{
    if parts.avma_range.is_empty() {
        return Err(ModuleError::EmptyAvmaRange);
    }
    if parts.eh_frame_svma.is_none() {
        return Err(ModuleError::MissingEhFrameSvma);
    }
    if parts.eh_frame.is_none() {
        return Err(ModuleError::MissingEhFrame);
    }
    if parts.eh_frame_hdr_svma.is_none() {
        return Err(ModuleError::MissingEhFrameHdrSvma);
    }
    if parts.eh_frame_hdr.is_none() {
        return Err(ModuleError::MissingEhFrameHdr);
    }
    let slide = parts.base_avma.wrapping_sub(parts.base_svma);
    let eh_frame_hdr = parts.eh_frame_hdr.as_ref().expect("checked above");
    let eh_frame_hdr_svma = parts.eh_frame_hdr_svma.as_ref().expect("checked above");
    EhFrameTable::parse(
        eh_frame_hdr,
        eh_frame_hdr_svma.start,
        parts.eh_frame_svma.as_ref().map(|r| r.start),
        parts.base_avma,
        parts.base_svma,
        parts.avma_range.start,
        eh_frame_hdr_svma.start.wrapping_add(slide),
    )
    .map_err(ModuleError::InvalidEhFrameHdr)?;
    Ok(())
}

/// Trait implemented by each architecture-specific unwinder.
pub trait Unwinder: Clone {
    type UnwindRegs;
    type Cache;
    type Module;

    fn add_module(&mut self, module: Self::Module);
    fn remove_module(&mut self, avma_start: u64);
    fn max_known_code_address(&self) -> u64;

    fn is_signal_frame(&self, _frame: FrameAddress, _regs: &Self::UnwindRegs) -> bool {
        false
    }

    fn unwind_frame<F>(
        &self,
        frame: FrameAddress,
        regs: &mut Self::UnwindRegs,
        cache: &mut Self::Cache,
        read_stack: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>;

    fn iter_frames<'u, 'c, 'r, F>(
        &'u self,
        pc: u64,
        regs: Self::UnwindRegs,
        cache: &'c mut Self::Cache,
        read_stack: &'r mut F,
    ) -> UnwindIterator<'u, 'c, 'r, Self, F>
    where
        Self: Sized,
        F: FnMut(u64) -> Result<u64, ()>,
    {
        UnwindIterator::new(self, pc, regs, cache, read_stack)
    }
}

pub struct UnwindIterator<'u, 'c, 'r, U, F>
where
    U: Unwinder,
    F: FnMut(u64) -> Result<u64, ()>,
{
    unwinder: &'u U,
    state: UnwindIteratorState,
    regs: U::UnwindRegs,
    cache: &'c mut U::Cache,
    read_stack: &'r mut F,
}

enum UnwindIteratorState {
    Initial(u64),
    Unwinding(FrameAddress),
    Done,
}

impl<'u, 'c, 'r, U, F> UnwindIterator<'u, 'c, 'r, U, F>
where
    U: Unwinder,
    F: FnMut(u64) -> Result<u64, ()>,
{
    fn new(
        unwinder: &'u U,
        pc: u64,
        regs: U::UnwindRegs,
        cache: &'c mut U::Cache,
        read_stack: &'r mut F,
    ) -> Self {
        Self {
            unwinder,
            state: UnwindIteratorState::Initial(pc),
            regs,
            cache,
            read_stack,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<FrameAddress>, Error> {
        let (return_address, interrupted_instruction_pointer) = match self.state {
            UnwindIteratorState::Initial(pc) => {
                let frame = FrameAddress::InstructionPointer(pc);
                self.state = UnwindIteratorState::Unwinding(frame);
                return Ok(Some(frame));
            }
            UnwindIteratorState::Unwinding(frame) => {
                let return_address = self.unwinder.unwind_frame(
                    frame,
                    &mut self.regs,
                    self.cache,
                    self.read_stack,
                )?;
                (
                    return_address,
                    self.unwinder.is_signal_frame(frame, &self.regs),
                )
            }
            UnwindIteratorState::Done => return Ok(None),
        };

        match return_address {
            Some(ra) => {
                let frame = if interrupted_instruction_pointer {
                    Some(FrameAddress::InstructionPointer(ra))
                } else {
                    FrameAddress::from_return_address(ra)
                };
                if let Some(frame) = frame {
                    self.state = UnwindIteratorState::Unwinding(frame);
                    Ok(Some(frame))
                } else {
                    self.state = UnwindIteratorState::Done;
                    Ok(None)
                }
            }
            None => {
                self.state = UnwindIteratorState::Done;
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_keeps_caller_section_storage_without_copying() {
        let eh_frame = vec![0x11, 0x22, 0x33, 0x44];
        let eh_frame_ptr = eh_frame.as_ptr();
        let eh_frame_hdr = vec![1, 0, 0];
        let eh_frame_hdr_ptr = eh_frame_hdr.as_ptr();

        let module = Module::new(
            "zero-copy".to_string(),
            0x1000..0x2000,
            0x1000,
            DwarfModuleSections {
                base_svma: 0x1000,
                text_svma: None,
                text: None,
                eh_frame_svma: Some(0x1100..0x1104),
                eh_frame: Some(eh_frame),
                eh_frame_hdr_svma: Some(0x1200..0x1203),
                eh_frame_hdr: Some(eh_frame_hdr),
            },
        );

        assert_eq!(module.data.eh_frame_local_ptr, eh_frame_ptr);
        assert_eq!(module.data.eh_frame_hdr_local_ptr, eh_frame_hdr_ptr);
    }
}
