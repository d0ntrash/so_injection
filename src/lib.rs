use goblin::elf::Elf;
use nix::libc::user_regs_struct;
use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use nix::Error;
use proc_maps::{get_process_maps, MapRange};
use std::ffi::c_void;
use std::path::Path;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};

/// Holds the state of the process to be restored later
struct Snapshot {
    registers: user_regs_struct,
    instruction: i64,
    pid: Pid,
}

impl Snapshot {
    /// Take new snapshot to save process's state
    fn new(pid: Pid) -> Result<Self, nix::Error> {
        // Get and save the current register values of the target process
        let registers = ptrace::getregs(pid)?;

        // Save the instruction at the current rip
        let instruction = ptrace::read(pid, registers.rip as *mut c_void)?;

        Ok(Self {
            registers,
            instruction,
            pid,
        })
    }

    /// Restore snapshot from saved state
    fn restore(self) -> Result<(), nix::Error> {
        // Restore the original registers
        ptrace::setregs(self.pid, self.registers)?;

        // Restore the saved instruction
        unsafe {
            ptrace::write(
                self.pid,
                self.registers.rip as *mut c_void,
                self.instruction as *mut c_void,
            )?
        };
        Ok(())
    }
}

/// Get MapRange for `so_name` in target process
fn get_so_map(pid: Pid, so_name: &str) -> Option<MapRange> {
    // Get Process map
    let maps = get_process_maps(pid.into()).expect("Failed to get the process map of: {pid}");
    for map in maps {
        if let Some(filename) = map.filename() {
            if Path::new(filename)
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.contains(so_name))
                .unwrap_or(false)
            {
                return Some(map);
            }
        }
    }
    None
}

/// Find an offset of a given function in a given ELF file by resolving symbols
fn get_function_offset(filename: &str, function_name: &str) -> Option<u64> {
    let data = std::fs::read(filename).expect("Cant read libc!");
    let obj = Elf::parse(&data).expect("Failed to parse ELF file");

    fn find_offset(
        symtab: &goblin::elf::Symtab,
        strtab: &goblin::strtab::Strtab,
        function_name: &str,
    ) -> Option<u64> {
        symtab
            .iter()
            .find(|sym| {
                if let Some(Ok(name_bytes)) = strtab.get(sym.st_name as usize) {
                    if let Ok(name) = std::str::from_utf8(name_bytes.as_bytes()) {
                        return name.trim_end_matches('\0') == function_name;
                    }
                }
                false
            })
            .map(|sym| sym.st_value)
    }

    // Try to find the function in dynsyms first
    if let Some(offset) = find_offset(&obj.dynsyms, &obj.dynstrtab, function_name) {
        return Some(offset);
    }

    // If not found in dynsyms, search in syms
    find_offset(&obj.syms, &obj.strtab, function_name)
}

/// Lets target process call mmap() and writes so_path to the new page
fn write_path_to_process(pid: Pid, so_path: &str) -> Result<u64, nix::Error> {
    // Attach to the target process
    ptrace::attach(pid)?;

    // Wait until the process stops
    waitpid(pid, None)?;

    let snapshot = Snapshot::new(pid)?;
    let mut regs = snapshot.registers.clone();

    // Set up the registers for the mmap() system call
    regs.rax = 9; // syscall for mmap()
    regs.rdi = 0;
    regs.rsi = so_path.len() as u64;
    regs.rdx = 5; // PROT_WRITE | PROT_READ
    regs.r10 = 0x22; // MAP_ANONYMOUS | MAP_PRIVATE
    regs.r8 = u64::MAX;
    regs.r9 = 0;

    // Overwrite registers
    ptrace::setregs(pid, regs)?;

    // Overwrite the instruction with a syscall (0x50f)
    unsafe { ptrace::write(pid, regs.rip as *mut c_void, 0x50f as *mut c_void)? };

    // Execute mmap() to map a new page
    ptrace::step(pid, None)?;
    waitpid(pid, None)?;

    // Get the address of the new page
    let mut regs_updated = ptrace::getregs(pid)?;
    let address = regs_updated.rax;

    snapshot.restore()?;

    // Write the shared object path to the new page in the target process memory
    let path_bytes = so_path.as_bytes();
    for chunk in path_bytes.chunks(8) {
        let mut padded_chunk = [0u8; 8];
        for (i, &byte) in chunk.iter().enumerate() {
            padded_chunk[i] = byte;
        }
        unsafe {
            ptrace::write(
                pid,
                regs_updated.rax as *mut c_void,
                u64::from_ne_bytes(padded_chunk) as *mut c_void,
            )?
        };
        regs_updated.rax += 8;
    }

    ptrace::detach(pid, None)?;

    // Return address of path in target process memory
    Ok(address)
}

/// Lets target process call dlopen to load a shared object
pub fn call_dlopen(pid: Pid, p_dlopen: u64, p_so_path: u64) -> Result<(), nix::Error> {
    // Attach to the target process
    ptrace::attach(pid)?;

    // Wait until the process stops
    waitpid(pid, None)?;

    let snapshot = Snapshot::new(pid)?;
    let mut regs = snapshot.registers.clone();

    regs.rdi = p_so_path;
    regs.rsi = 1; // RTLD_LAZY
    regs.r9 = p_dlopen;

    ptrace::setregs(pid, regs)?;

    // call r9; int 3  0xccd1ff41
    unsafe {
        ptrace::write(
            pid,
            snapshot.registers.rip as *mut c_void,
            0xccd1ff41 as *mut c_void,
        )?
    };
    ptrace::cont(pid, None)?;
    waitpid(pid, None)?;

    snapshot.restore()?;

    ptrace::detach(pid, None)?;
    Ok(())
}

pub fn inject_by_pid(pid: i32, path: &str) -> Result<(), nix::Error> {
    inject(Pid::from_raw(pid), path)?;
    Ok(())
}

pub fn inject_by_name(process_name: &str, path: &str) -> Result<(), nix::Error> {
    // Get process id of target process
    let s = System::new_all();
    let pid = nix::unistd::Pid::from_raw(
        s.processes_by_exact_name(process_name)
            .next()
            .unwrap()
            .pid()
            .as_u32()
            .try_into()
            .unwrap(),
    );
    inject(pid, path)?;
    Ok(())
}

fn inject(pid: Pid, path: &str) -> Result<(), Error> {
    // TODO: Fix error handling
    let tmp_path = std::fs::canonicalize(path).unwrap();
    let absolute_path = tmp_path.to_str().unwrap();

    // Get map range of libc mapped in target process
    let libc_map = get_so_map(pid, "libc.").unwrap();

    let dlopen_offset =
        get_function_offset(libc_map.filename().unwrap().to_str().unwrap(), "dlopen")
            .expect("Function not found");
    let p_dlopen = libc_map.start() as u64 + dlopen_offset;

    // Write path string to into target process address space
    let p_so_path = write_path_to_process(pid, &(absolute_path.to_owned() + "\x00")).unwrap();

    // Call dlopen from target process
    call_dlopen(pid, p_dlopen, p_so_path)?;
    Ok(())
}
