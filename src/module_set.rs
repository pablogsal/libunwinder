use std::collections::BTreeMap;
use std::sync::Arc;

use crate::error::UnwindInfoError;
use crate::module::{LocalSection, ModuleData};

/// Per-unwinder registry of loaded modules and their local section
/// mirrors.
///
/// Two indices, both keyed by start address (in tracee virtual memory):
///
/// - `modules`: `avma_range.start` -> `ModuleData`. Used by
///   `find_proc_info` to locate the module containing an IP.
/// - `redirects`: `avma_start` of a locally-mirrored section ->
///   `(LocalSection, owner)`. Used by `access_mem` to short-circuit reads
///   of `.eh_frame` and `.eh_frame_hdr` away from the per-byte ptrace path.
pub(crate) struct ModuleSet {
    modules: BTreeMap<u64, Arc<ModuleData>>,
    redirects: BTreeMap<u64, RedirectEntry>,
}

struct RedirectEntry {
    section: LocalSection,
    /// Holds an `Arc` to the owning module so the local pointer stays
    /// alive for as long as the redirect is registered.
    _owner: Arc<ModuleData>,
}

impl ModuleSet {
    pub fn new() -> Self {
        Self {
            modules: BTreeMap::new(),
            redirects: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, data: Arc<ModuleData>) {
        let key = data.avma_range.start;
        for sec in &data.local_sections {
            self.redirects.insert(
                sec.avma_start,
                RedirectEntry {
                    section: LocalSection {
                        avma_start: sec.avma_start,
                        avma_end: sec.avma_end,
                        local_ptr: sec.local_ptr,
                    },
                    _owner: Arc::clone(&data),
                },
            );
        }
        self.modules.insert(key, data);
    }

    pub fn remove(&mut self, avma_start: u64) {
        if let Some(data) = self.modules.remove(&avma_start) {
            for sec in &data.local_sections {
                self.redirects.remove(&sec.avma_start);
            }
        }
    }

    pub fn max_known_code_address(&self) -> u64 {
        self.modules
            .values()
            .map(|module| module.avma_range.end)
            .max()
            .unwrap_or(0)
    }

    /// Find the module whose `avma_range` contains `addr`. O(log n).
    pub fn find_module(&self, addr: u64) -> Option<&Arc<ModuleData>> {
        let (_, data) = self.modules.range(..=addr).next_back()?;
        if addr >= data.avma_range.start && addr < data.avma_range.end {
            Some(data)
        } else {
            None
        }
    }

    pub fn has_unwind_info(&self, addr: u64) -> bool {
        self.find_module(addr).is_some_and(|module| {
            module.table.entry_count != 0
                && !module.eh_frame_hdr_local_ptr.is_null()
                && !module.eh_frame_local_ptr.is_null()
        })
    }

    pub fn contains_address(&self, addr: u64) -> bool {
        self.find_module(addr).is_some()
    }

    pub fn unwind_info_error(&self, addr: u64) -> Option<UnwindInfoError> {
        let module = self.find_module(addr)?;
        module
            .eh_frame_hdr_error
            .map(|source| UnwindInfoError::InvalidEhFrameHdr {
                module: module.name.clone(),
                source,
            })
    }

    pub fn is_signal_frame(&self, addr: u64) -> bool {
        let Some(module) = self.find_module(addr) else {
            return false;
        };
        let Ok(cache) = module.function_cache.lock() else {
            return false;
        };
        cache
            .range(..=addr)
            .next_back()
            .is_some_and(|(_, details)| addr < details.end_ip && details.signal_frame)
    }

    /// Look up an 8-byte read at `addr` in the local-section redirect
    /// table. Returns the local pointer iff the full 8-byte range fits
    /// inside a registered local section.
    ///
    /// # Safety contract
    /// Caller must read exactly 8 bytes through the returned pointer.
    pub fn lookup_local(&self, addr: u64) -> Option<*const u8> {
        let (_, entry) = self.redirects.range(..=addr).next_back()?;
        let sec = &entry.section;
        if addr >= sec.avma_start && addr.saturating_add(8) <= sec.avma_end {
            let offset = (addr - sec.avma_start) as usize;
            // SAFETY: bounds verified above. `local_ptr` is valid for the
            // section's lifetime, held by `_owner`.
            Some(unsafe { sec.local_ptr.add(offset) })
        } else {
            None
        }
    }
}

impl Clone for ModuleSet {
    fn clone(&self) -> Self {
        let mut cloned = Self::new();
        for module in self.modules.values() {
            cloned.add(Arc::clone(module));
        }
        cloned
    }
}
