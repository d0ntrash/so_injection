#[cfg(test)]
mod tests {
    use crate::{get_so_map, inject_by_pid};
    use nix::unistd::Pid;
    use std::process::{Command, Stdio};
    use std::{thread, time};

    // // Only used for manual testing to observe the injection in the remote process
    // // Usage: Start `tail` in another terminal befor running the test
    // #[test]
    // fn test_inject_by_name() {
    //  use crate::inject_by_name; 
    // 	use std::path::Path;
    // 	use std::env;
    // 	// Get the path of the example so
    // 	let current_dir = env::current_dir().unwrap();
    // 	let path = current_dir.join("target/debug/deps/libexample_so.so");

    // 	// Wait for libc to be loaded
    // 	thread::sleep(time::Duration::from_millis(10));

    // 	assert!(inject_by_name("tail", path.to_str().unwrap()).is_ok())
    // }

    #[test]
    fn test_inject_by_pid() {
        use std::env;
        // Get the path of the example so
        let current_dir = env::current_dir().unwrap();
        let path = current_dir.join("target/debug/deps/libexample_so.so");

        // Start target process
        let mut child = Command::new("tail")
            .arg("/bin/ls")
            .arg("-f")
            .stdout(Stdio::null())
            .spawn()
            .expect("Failed to execute sleep command");
        let pid = child.id() as i32;

        // Wait for libc to be loaded
        thread::sleep(time::Duration::from_millis(10));

        inject_by_pid(pid, path.to_str().unwrap()).unwrap();

        // Wait for implant to be loaded
        thread::sleep(time::Duration::from_millis(10));

        let map = get_so_map(Pid::from_raw(pid), "libexample");
        assert!(map.is_ok());

        // Kill target process
        child.kill().unwrap();
    }

    #[test]
    fn test_get_so_map() {
        // Start target process
        let mut child = Command::new("tail")
            .arg("/bin/ls")
            .arg("-f")
            .stdout(Stdio::null())
            .spawn()
            .expect("Failed to execute sleep command");
        let pid = child.id() as i32;

        // Wait for libc to be loaded
        thread::sleep(time::Duration::from_millis(10));

        let map = get_so_map(Pid::from_raw(pid), "libc.");
        assert!(map.is_ok());

        // Kill target process
        child.kill().unwrap();
    }
}
