use goblin::elf::Elf;
use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use proc_maps::{get_process_maps, MapRange};
use std::{ffi::c_void, println};
use std::path::Path;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};

/// Get MapRange for libc in target process
fn get_so_map(pid: Pid, so_name: &str) -> Option<MapRange> {
    // Get Process map
    let maps = get_process_maps(pid.into()).expect("Failed to get the process map of: {pid}");
    for map in maps {
        if let Some(filename) = map.filename() {
            if Path::new(filename).file_name()
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

/// Find a offset of a given function in a given ELF file by resolving symbols
fn get_function_offset(filename: &str, function_name: &str) -> Option<u64> {
    let data = std::fs::read(filename).expect("Cant read libc!");
    let obj = Elf::parse(&data)
        .map_err(|_| "cannot parse ELF file")
        .unwrap();
    // Iterate dyntab
    let dyntab = obj.dynstrtab;
    for sym in obj.dynsyms.into_iter() {
        if (dyntab[sym.st_name]).eq(function_name) {
            return Some(sym.st_value);
        }
    }
    // Iterate strtab
    let strtab = obj.strtab;
    for sym in obj.syms.into_iter() {
        if (strtab[sym.st_name]).eq(function_name) {
            return Some(sym.st_value);
        }
    }
    None
}

/// Lets target process call mmap() and writes so_path to the new page
fn write_path_to_process(pid: Pid, so_path: &str) -> u64 {
    // Attaching to process
    // Pauses process execution
    ptrace::attach(pid).unwrap();

    // Wait until process stops
    waitpid(pid, None).unwrap();

    // Get and save current register values of target process
    let mut regs = ptrace::getregs(pid).unwrap();
    let regs_saved = regs;

    // Save instruction which will bi overwritten
    let saved_instruction = ptrace::read(pid, regs.rip as *mut c_void).unwrap();

    regs.rax = 9; // syscall for mmap()
    regs.rdi = 0;
    regs.rsi = so_path.len() as u64;
    regs.rdx = 5; // PROT_WRITE | PROT_READ
    regs.r10 = 0x22; // MAP_ANONYMOUS | MAP_PRIVATE
    regs.r8 = u64::MAX;
    regs.r9 = 0;

    // Overwrite registers
    ptrace::setregs(pid, regs).unwrap();

    // Overwrite instruction with syscall (0x50f)
    unsafe { ptrace::write(pid, regs.rip as *mut c_void, 0x50f as *mut c_void).unwrap() };

    // Execute mmap to map new page
    ptrace::step(pid, None).unwrap();
    waitpid(pid, None).unwrap();

    // Get address of new page
    let mut regs_updated = ptrace::getregs(pid).unwrap();
    let address = regs_updated.rax;

    // Restore registers
    ptrace::setregs(pid, regs_saved).unwrap();

    // Restore saved instruction
    unsafe {
        ptrace::write(
            pid,
            regs_saved.rip as *mut c_void,
            saved_instruction as *mut c_void,
        )
        .unwrap()
    };

    // Write padded string to new page
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
            )
            .unwrap()
        };
        regs_updated.rax += 8;
    }

    ptrace::detach(pid, None).unwrap();

    // Return address of path in target process memory
    address
}

/// Lets target process call dlopen to load a shared object
pub fn call_dlopen(pid: Pid, p_dlopen: u64, p_so_path: u64) {
    // Attaching to process
    // Pauses process execution
    ptrace::attach(pid).unwrap();

    // Wait stops
    waitpid(pid, None).unwrap();

    // Get and save current register values of target process
    let mut regs = ptrace::getregs(pid).unwrap();
    let regs_saved = regs;
    let saved_instruction = ptrace::read(pid, regs.rip as *mut c_void).unwrap();

    regs.rdi = p_so_path;
    regs.rsi = 1; // RTLD_LAZY
    regs.r9 = p_dlopen;

    ptrace::setregs(pid, regs).unwrap();

    // call r9; int 3  0xccd1ff41
    unsafe {
        ptrace::write(
            pid,
            regs_saved.rip as *mut c_void,
            0xccd1ff41 as *mut c_void,
        )
        .unwrap()
    };
    ptrace::cont(pid, None).unwrap();
    waitpid(pid, None).unwrap();

    ptrace::setregs(pid, regs_saved).unwrap();
    unsafe {
        ptrace::write(
            pid,
            regs_saved.rip as *mut c_void,
            saved_instruction as *mut c_void,
        )
        .unwrap()
    };
    ptrace::detach(pid, None).unwrap();
}

pub fn inject_by_pid(pid: i32, path: &str) {
    inject(Pid::from_raw(pid), path);
}

pub fn inject_by_name(process_name: &str, path: &str) {
    // Get process id of target process
    let s = System::new_all();
    let pid = nix::unistd::Pid::from_raw(
        s.processes_by_exact_name(process_name)
            .next()
            .expect("Process not found!")
            .pid()
            .as_u32()
            .try_into()
            .unwrap(),
    );
    inject(pid, path);
}

fn inject(pid: Pid, path: &str) {
    let tmp_path = std::fs::canonicalize(path).unwrap();
    let absolute_path = tmp_path.to_str().unwrap();
    
    // Get map range of libc mapped in target process
    let libc_map = get_so_map(pid, "libc.").expect("libc map not found!");

    let dlopen_offset =
        get_function_offset(libc_map.filename().unwrap().to_str().unwrap(), "dlopen")
            .expect("Function not found");
    let p_dlopen = libc_map.start() as u64 + dlopen_offset;
    
    // Write path string to into target process address space
    let p_so_path = write_path_to_process(pid, &(absolute_path.to_owned() + "\x00"));

    // Call dlopen from target process
    call_dlopen(pid, p_dlopen, p_so_path);
}

#[cfg(test)]
mod tests {
    use std::process::{Stdio, Command};
    use nix::unistd::Pid;
    use crate::{get_so_map, inject_by_pid};
    use std::{thread, time};
    
    #[test]
    fn test_inject_by_pid() {
	use std::path::Path;
	use std::env;
	// Get the path of the example so
	let current_dir = env::current_dir().unwrap();
	let path = current_dir.join("target/debug/deps/libexample_so.so");
	
	// Start target process
	let mut child = Command::new("tail").arg("/bin/ls").arg("-f").stdout(Stdio::null()).spawn().expect("Failed to execute sleep command");
	let pid = child.id() as i32;
	
	// Wait for libc to be loaded
	thread::sleep(time::Duration::from_millis(10));

	inject_by_pid(pid, path.to_str().unwrap());

	// Wait for implant to be loaded
	thread::sleep(time::Duration::from_millis(10));

	let map = get_so_map(Pid::from_raw(pid), "libexample");
	assert!(map.is_some());

	// Kill target process
	child.kill().unwrap();
    }
    
    #[test]
    fn test_get_so_map() {
	// Start target process
	let mut child = Command::new("tail").arg("/bin/ls").arg("-f").stdout(Stdio::null()).spawn().expect("Failed to execute sleep command");
	let pid = child.id() as i32;
	
	// Wait for libc to be loaded
	thread::sleep(time::Duration::from_millis(10));
	
	let map = get_so_map(Pid::from_raw(pid), "libc.");
	assert!(map.is_some());

	// Kill target process
	child.kill().unwrap();
    }
}
