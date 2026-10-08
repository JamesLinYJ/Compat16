//! DOS image loading and initial machine layout.

use crate::{Runtime, RuntimeError, DiagnosticKind as Kind, XMS_ENTRY, runtime_error};
use x86_cpu::Cpu;
use devices::BiosDevices;
use devices::ports::MachinePorts;
use crate::clock::DeviceClock;
use formats::{load_executable, parse_ne, ImageKind};
use guest_core::{real_address, GuestMemory, MemoryError, PhysAddr};
use guest_core::memory::{Memory, MemoryStorage, DEFAULT_MEMORY_SIZE};
use guest_core::arena::{PhysicalArenaMap, RegionKind};
use xms::{XmsConfig, XmsService};

/// Runtime placement policy: larger process environments can move the PSP up.
pub const MINIMUM_PSP_SEGMENT: u16 = 0x1000;
// Place the environment's MCB immediately after the DOS system reservation.
const ENV_SEGMENT: u16 = dos_kernel::SYSTEM_SEGMENT + (dos_kernel::SYSTEM_BYTES / 16) as u16 + 1;
const CONVENTIONAL_END: u32 = 0xa0000;

impl Runtime {
    /// Required backing size for the current DOS/Win16 memory-layout policy.
    pub fn memory_size_for_image(image: &[u8]) -> u32 {
        if parse_ne(image).is_ok() { crate::win16_runtime::PE32_MEMORY_END }
        else { DEFAULT_MEMORY_SIZE }
    }

    pub fn load(image: &[u8], command_tail: &[u8], program_path: &[u8]) -> Result<Self, RuntimeError> {
        Self::load_with_environment(image, command_tail, program_path, &[])
    }

    /// Load a process with an independent copy of its inherited OEM environment.
    /// The host prepares text; DOS owns block layout and guest addresses.
    pub fn load_with_environment(image: &[u8], command_tail: &[u8], program_path: &[u8],
        environment_entries: &[Vec<u8>]) -> Result<Self, RuntimeError> {
        Self::load_with_environment_and_win16_path(
            image, command_tail, program_path, program_path, environment_entries,
        )
    }

    /// Keep the DOS virtual-drive/OEM path independent of the Win16 module's
    /// native ANSI identity. Resource access and DLL search must reopen the
    /// actual main-module file through the same namespace as host file APIs.
    pub fn load_with_environment_and_win16_path(
        image: &[u8], command_tail: &[u8], program_path: &[u8],
        win16_main_path: &[u8], environment_entries: &[Vec<u8>],
    ) -> Result<Self, RuntimeError> {
        Self::load_with_storage(image, command_tail, program_path, win16_main_path,
            environment_entries, None)
    }

    /// Load with an optional host-owned, initialized backing. The injected
    /// store becomes the single guest RAM owner; it must have the exact size
    /// returned by `memory_size_for_image`. Native addresses stay in the host.
    pub fn load_with_storage(
        image: &[u8], command_tail: &[u8], program_path: &[u8],
        win16_main_path: &[u8], environment_entries: &[Vec<u8>],
        storage: Option<Box<dyn MemoryStorage>>,
    ) -> Result<Self, RuntimeError> {
        if command_tail.len() > 126 { return Err(RuntimeError::new(Kind::InvalidInput, "DOS command tail exceeds 126 bytes")); }
        if program_path.contains(&0) || program_path.len() > 1024 { return Err(RuntimeError::new(Kind::InvalidInput, "invalid DOS executable path")); }
        let environment = crate::environment::EnvironmentBlock::new(environment_entries, program_path)?;
        let ne_module = parse_ne(image).ok();
        // Keep the existing minimum load location, moving it upward when the
        // inherited environment requires more room. One paragraph holds the
        // program's MCB; environment bytes can never overlap that header/PSP.
        // A protected task also needs an independently owned PDB allocation.
        // Its 16 data paragraphs and both MCB headers must fit in the free gap;
        // this is loader placement policy, not a guest ABI address constant.
        let process_gap = if ne_module.is_some() {
            (win16_abi::pdb::PDB_PREFIX_LEN / 16 + 2) as u16
        } else { 1 };
        let psp_segment = ENV_SEGMENT.checked_add(environment.paragraphs)
            .and_then(|segment| segment.checked_add(process_gap)).map(|segment| segment.max(MINIMUM_PSP_SEGMENT))
            .ok_or_else(|| RuntimeError::new(Kind::InvalidInput, "DOS environment leaves no program segment"))?;
        if ne_module.is_some() && (win16_main_path.is_empty() || win16_main_path.contains(&0)) {
            return Err(RuntimeError::new(Kind::InvalidInput, "invalid Win16 executable path"));
        }
        let required_size = Self::memory_size_for_image(image);
        let mut memory = match storage {
            Some(storage) => {
                let memory = Memory::with_storage(storage).map_err(runtime_error)?;
                if memory.size_bytes() != required_size {
                    return Err(RuntimeError::new(Kind::InvalidInput,
                        "provided guest storage size does not match the image memory layout"));
                }
                memory
            }
            None => Memory::with_size(required_size).map_err(runtime_error)?,
        };
        let mut arenas = PhysicalArenaMap::new(memory.len()).map_err(runtime_error)?;
        let system_start = u32::from(dos_kernel::SYSTEM_SEGMENT) * 16;
        let system_end = system_start + dos_kernel::SYSTEM_BYTES as u32;
        arenas.reserve(RegionKind::ConventionalMemory, PhysAddr(0), system_start, 16).map_err(runtime_error)?;
        arenas.reserve(RegionKind::DosSystem, PhysAddr(system_start), system_end - system_start, 16).map_err(runtime_error)?;
        arenas.reserve(RegionKind::ConventionalMemory, PhysAddr(system_end), CONVENTIONAL_END - system_end, 16).map_err(runtime_error)?;
        arenas.reserve(RegionKind::VideoMemory, PhysAddr(0xa0000), 0x20000, 16).map_err(runtime_error)?;
        arenas.reserve(RegionKind::BiosRom, PhysAddr(0xf0000), 0x10000, 16).map_err(runtime_error)?;
        arenas.reserve(RegionKind::Hma, PhysAddr(0x100000), 0xfff0, 16).map_err(runtime_error)?;
        let xms_config = XmsConfig::default();
        let xms_region = arenas.reserve(RegionKind::Xms, xms_config.arena_start,
            xms_config.arena_end.0.checked_sub(xms_config.arena_start.0).ok_or_else(|| RuntimeError::new(Kind::InternalInvariant, "invalid XMS arena"))?, 1024)
            .map_err(runtime_error)?;
        let win16_region_id = if ne_module.is_some() {
            Some(arenas.reserve(
                RegionKind::Win16,
                PhysAddr(crate::win16_runtime::WIN16_ARENA_BASE),
                crate::win16_runtime::WIN16_MEMORY_END - crate::win16_runtime::WIN16_ARENA_BASE,
                0x1000,
            ).map_err(runtime_error)?)
        } else { None };
        let pe32_region_id = if ne_module.is_some() {
            Some(arenas.reserve(
                RegionKind::Pe32,
                PhysAddr(crate::win16_runtime::PE32_MEMORY_BASE),
                crate::win16_runtime::PE32_MEMORY_END
                    - crate::win16_runtime::PE32_MEMORY_BASE,
                0x1000,
            ).map_err(runtime_error)?)
        } else {
            None
        };
        let xms_region = arenas.get(xms_region).map_err(runtime_error)?;
        let mut xms = XmsService::with_config(XmsConfig { arena_start: xms_region.base(), arena_end: xms_region.end_exclusive() })
            .map_err(|error| RuntimeError::with_source(Kind::InternalInvariant, "configure XMS arena", error))?;
        let mut devices = BiosDevices::new();
        let vga = devices.video.vga().clone();
        memory.map_device(PhysAddr(0xa0000), 0x20000, std::rc::Rc::new(vga.clone()))
            .map_err(runtime_error)?;
        memory.initialize_rom(guest_core::real_address(
            devices::vga::bios::FUNCTIONALITY_SEGMENT,
            devices::vga::bios::FUNCTIONALITY_OFFSET,
        ), &devices::vga::bios::functionality_table()).map_err(runtime_error)?;
        devices.initialize(&mut memory)
            .map_err(|error| RuntimeError::with_source(Kind::InternalInvariant, "initialize machine BIOS data", error))?;
        memory.initialize_rom(real_address(XMS_ENTRY.segment, XMS_ENTRY.offset), &[0xcb])
            .map_err(|error| RuntimeError::with_source(Kind::InternalInvariant, "install XMS firmware", error))?;
        crate::interrupts::install_service_entries(&mut memory)?;
        let mut ports = MachinePorts::with_vga(vga);
        crate::hardware_interrupts::initialize(&mut memory, &mut ports)?;
        let mut dos = dos_kernel::DosKernel::new(psp_segment);
        crate::nls::install(&mut memory, &mut dos)?;
        if ne_module.is_some() {
            xms.enable_local_a20().map_err(|error| RuntimeError::with_source(
                Kind::InternalInvariant, "enable A20 for Win16 selector memory", error,
            ))?;
        }
        memory.set_a20_enabled(xms.a20_state().enabled)?;
        let loaded = if ne_module.is_none() {
            Some(load_executable(image, psp_segment, &mut Conventional(&mut memory)).map_err(runtime_error)?)
        } else {
            None
        };
        let mut psp = [0u8; 256];
        psp[0..2].copy_from_slice(&[0xcd, 0x20]);
        psp[2..4].copy_from_slice(&((CONVENTIONAL_END / 16) as u16).to_le_bytes());
        psp[0x16..0x18].copy_from_slice(&psp_segment.to_le_bytes());
        psp[0x18..0x2c].fill(0xff);
        psp[0x18..0x1b].copy_from_slice(&[0, 1, 2]);
        psp[0x2c..0x2e].copy_from_slice(&ENV_SEGMENT.to_le_bytes());
        psp[0x32..0x34].copy_from_slice(&20u16.to_le_bytes());
        psp[0x34..0x36].copy_from_slice(&0x18u16.to_le_bytes());
        psp[0x36..0x38].copy_from_slice(&psp_segment.to_le_bytes());
        psp[0x50..0x53].copy_from_slice(&[0xcd, 0x21, 0xcb]);
        psp[0x80] = command_tail.len() as u8;
        psp[0x81..0x81 + command_tail.len()].copy_from_slice(command_tail);
        psp[0x81 + command_tail.len()] = 0x0d;
        memory.write(real_address(psp_segment, 0), &psp).map_err(runtime_error)?;
        memory.write(real_address(ENV_SEGMENT, 0), &environment.bytes).map_err(runtime_error)?;
        dos.initialize_process_arena(&mut memory, ENV_SEGMENT, environment.paragraphs,
            (CONVENTIONAL_END / 16) as u16).map_err(runtime_error)?;
        dos.initialize_system_tables(&mut memory).map_err(runtime_error)?;
        dos.initialize_character_devices(&mut memory).map_err(runtime_error)?;
        if loaded.as_ref().is_some_and(|image| image.kind == ImageKind::Com) {
            memory.write_u16(real_address(psp_segment, 0xfffe), 0).map_err(runtime_error)?;
        }
        let (win16, mut regs) = if let Some(module) = &ne_module {
            let pe32_region = arenas.get(pe32_region_id.ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "Win16 image has no PE32 memory reservation",
            ))?).map_err(runtime_error)?;
            let win16_region = arenas.get(win16_region_id.ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "Win16 image has no Win16 memory reservation",
            ))?).map_err(runtime_error)?;
            let (state, registers) = crate::win16_runtime::Win16State::load(
                image, module, crate::win16_runtime::Win16ProcessBootstrap {
                    canonical_psp: psp_segment,
                    environment_segment: ENV_SEGMENT,
                    environment_logical_bytes: environment.bytes.len(),
                }, win16_main_path, &mut dos, &mut memory, pe32_region, win16_region,
            )?;
            (Some(state), registers)
        } else {
            (None, loaded.expect("DOS image was loaded").registers)
        };
        regs.eflags = 0x0202;
        let rendered_video_version = devices.video.version();
        Ok(Self { memory, cpu: Cpu::new(regs), dos,
            devices, ports, port_clock: DeviceClock::new(),
            xms, arenas, instructions: 0, rendered_video_version,
            rendered_graphics_version: None, instruction_trace: None,
            memory_write_watch: None,
            input: crate::input::MouseInputBridge::new(), rendered_mouse_cursor: None,
            process_frames: Vec::new(), win16 })
    }

}

/// Loader allocation may only consume the DOS conventional-memory region.
struct Conventional<'a>(&'a mut Memory);
impl GuestMemory for Conventional<'_> {
    fn len(&self) -> u32 { CONVENTIONAL_END.min(self.0.len()) }
    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.validate_read(address, bytes.len())?;
        self.0.read(address, bytes)
    }
    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.validate_write(address, bytes.len())?;
        self.0.write(address, bytes)
    }
}

#[cfg(test)]
#[path = "load_tests.rs"]
mod tests;
