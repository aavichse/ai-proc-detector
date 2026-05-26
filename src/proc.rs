#![allow(dead_code)]

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStat {
    pub starttime: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessType {
    ElfBinary,
    Node,
    Python,
    Shell,
    Unknown,
}

use procfs::process::Process;

/// Safely parses /proc/<pid>/stat to get process information.
/// Uses the starttime to uniquely identify a process instance.
pub fn get_stat(pid: u32) -> Result<ProcStat> {
    let prc = Process::new(pid as i32).with_context(|| format!("Failed to open process {}", pid))?;
    let stat = prc.stat().with_context(|| format!("Failed to read stat for {}", pid))?;
    
    Ok(ProcStat { starttime: stat.starttime })
}

/// Determines the type of process by inspecting its executable.
/// It checks if the resolved executable name indicates Python, Node, or Shell.
/// Otherwise, it checks the magic bytes for an ELF binary.
pub fn get_process_type(pid: u32) -> Result<ProcessType> {
    let prc = match Process::new(pid as i32) {
        Ok(p) => p,
        Err(_) => return Err(anyhow::anyhow!("Failed to open process {}", pid)),
    };
    
    let exe_path = match prc.exe() {
        Ok(path) => path,
        Err(e) => return Err(anyhow::anyhow!("Failed to read link for /proc/{}/exe: {}", pid, e)),
    };

    let file_name = exe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    if file_name.contains("python") {
        return Ok(ProcessType::Python);
    }
    if file_name.contains("node") {
        return Ok(ProcessType::Node);
    }
    if matches!(file_name.as_str(), "bash" | "sh" | "zsh" | "dash") {
        return Ok(ProcessType::Shell);
    }

    // Check magic bytes for ELF
    if let Ok(mut file) = fs::File::open(&exe_path) {
        let mut magic = [0u8; 4];
        if file.read_exact(&mut magic).is_ok() && magic == [0x7f, b'E', b'L', b'F'] {
            return Ok(ProcessType::ElfBinary);
        }
    }

    Ok(ProcessType::Unknown)
}

/// Reads the command line arguments of a process from /proc/<pid>/cmdline.
/// Returns a vector of strings, one for each argument.
pub fn get_cmdline(pid: u32) -> Result<Vec<String>> {
    let prc = Process::new(pid as i32).with_context(|| format!("Failed to open process {}", pid))?;
    let cmdline = prc.cmdline().with_context(|| format!("Failed to read cmdline for {}", pid))?;
    
    Ok(cmdline)
}

/// Reads /proc/<pid>/maps and returns a list of unique file paths that are mapped into the process memory.
pub fn get_mapped_files(pid: u32) -> Result<Vec<String>> {
    let prc = Process::new(pid as i32).with_context(|| format!("Failed to open process {}", pid))?;
    let maps = prc.maps().with_context(|| format!("Failed to read maps for {}", pid))?;

    let mut files = Vec::new();
    for map in maps {
        if let procfs::process::MMapPath::Path(path) = map.pathname {
            if let Some(pathname) = path.to_str() {
                if pathname.starts_with('/') {
                    files.push(pathname.to_string());
                }
            }
        }
    }

    files.sort();
    files.dedup();
    Ok(files)
}

/// Returns a list of child process PIDs for the given PID.
/// This implementation uses procfs to fetch task children.
pub fn get_child_pids(pid: u32) -> Result<Vec<u32>> {
    let prc = Process::new(pid as i32).with_context(|| format!("Failed to open process {}", pid))?;
    let mut children = Vec::new();

    if let Ok(tasks) = prc.tasks() {
        for task_res in tasks {
            if let Ok(task) = task_res {
                if let Ok(child_list) = task.children() {
                    for child_pid in child_list {
                        children.push(child_pid as u32);
                    }
                }
            }
        }
    }

    children.sort();
    children.dedup();
    Ok(children)
}

pub fn check_stdio_is_socket(pid: u32) -> Result<(bool, bool)> {
    let prc = Process::new(pid as i32).with_context(|| format!("Failed to open process {}", pid))?;
    let fds = prc.fd().with_context(|| format!("Failed to read fd mapping for {}", pid))?;

    let mut is_stdin_socket = false;
    let mut is_stdout_socket = false;

    for fd_res in fds {
        if let Ok(fd_entry) = fd_res {
            if fd_entry.fd == 0 {
                if let procfs::process::FDTarget::Socket(_) = fd_entry.target {
                    is_stdin_socket = true;
                } else if let procfs::process::FDTarget::Pipe(_) = fd_entry.target {
                    is_stdin_socket = true;
                }
            } else if fd_entry.fd == 1 {
                if let procfs::process::FDTarget::Socket(_) = fd_entry.target {
                    is_stdout_socket = true;
                } else if let procfs::process::FDTarget::Pipe(_) = fd_entry.target {
                    is_stdout_socket = true;
                }
            }
        }
    }

    Ok((is_stdin_socket, is_stdout_socket))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixSockEntry {
    pub inode: u64,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcFdEntry {
    pub pid: u32,
    pub fd: i32,
    pub inode: u64,
    pub path: String,
}

fn parse_proc_net_unix_line(line: &str) -> Option<UnixSockEntry> {
    // /proc/net/unix columns are:
    // Num RefCount Protocol Flags Type St Inode Path
    let mut parts = line.split_whitespace();
    let _num = parts.next()?;
    let _ref_count = parts.next()?;
    let _protocol = parts.next()?;
    let _flags = parts.next()?;
    let _sock_type = parts.next()?;
    let _state = parts.next()?;
    let inode_str = parts.next()?;
    let path = parts.next()?;

    if !path.ends_with(".sock") {
        return None;
    }

    let inode = inode_str.parse::<u64>().ok()?;
    Some(UnixSockEntry {
        inode,
        path: path.to_string(),
    })
}

/// Returns all filesystem-backed unix sockets ending with `.sock` from /proc/net/unix.
pub fn list_unix_sock_entries() -> Result<Vec<UnixSockEntry>> {
    let content = fs::read_to_string("/proc/net/unix")
        .context("Failed to read /proc/net/unix")?;

    let mut out = Vec::new();
    for line in content.lines().skip(1) {
        if let Some(entry) = parse_proc_net_unix_line(line) {
            out.push(entry);
        }
    }

    out.sort_by(|a, b| a.path.cmp(&b.path).then(a.inode.cmp(&b.inode)));
    out.dedup_by(|a, b| a.inode == b.inode && a.path == b.path);
    Ok(out)
}

/// Correlates `.sock` unix sockets to owning process pid/fd by joining inode from
/// /proc/net/unix with /proc/<pid>/fd/* symlink targets (`socket:[inode]`).
pub fn list_ipc_sock_pid_fds() -> Result<Vec<IpcFdEntry>> {
    let sock_entries = list_unix_sock_entries()?;
    if sock_entries.is_empty() {
        return Ok(Vec::new());
    }

    let inode_to_path: HashMap<u64, String> = sock_entries
        .into_iter()
        .map(|e| (e.inode, e.path))
        .collect();

    let mut out = Vec::new();
    for proc_dir in fs::read_dir("/proc").context("Failed to read /proc")? {
        let proc_dir = match proc_dir {
            Ok(v) => v,
            Err(_) => continue,
        };

        let pid: u32 = match proc_dir.file_name().to_string_lossy().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let fd_dir = proc_dir.path().join("fd");
        let fd_iter = match fs::read_dir(&fd_dir) {
            Ok(v) => v,
            Err(_) => continue,
        };

        for fd_entry in fd_iter {
            let fd_entry = match fd_entry {
                Ok(v) => v,
                Err(_) => continue,
            };

            let fd: i32 = match fd_entry.file_name().to_string_lossy().parse() {
                Ok(v) => v,
                Err(_) => continue,
            };

            let target = match fs::read_link(fd_entry.path()) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let target_str = target.to_string_lossy();
            if !target_str.starts_with("socket:[") || !target_str.ends_with(']') {
                continue;
            }

            let inode_str = &target_str[8..target_str.len() - 1];
            let inode: u64 = match inode_str.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };

            let Some(path) = inode_to_path.get(&inode) else {
                continue;
            };

            out.push(IpcFdEntry {
                pid,
                fd,
                inode,
                path: path.clone(),
            });
        }
    }

    out.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.pid.cmp(&b.pid))
            .then(a.fd.cmp(&b.fd))
    });
    out.dedup_by(|a, b| a.pid == b.pid && a.fd == b.fd && a.inode == b.inode);
    Ok(out)
}

/// Returns pid/fd/inode/path IPC entries filtered by a caller-provided predicate.
///
/// Example:
/// `list_ipc_sock_pid_fds_filtered(|e| e.path.contains("mcp"))`
pub fn list_ipc_sock_pid_fds_filtered<F>(handler: F) -> Result<Vec<IpcFdEntry>>
where
    F: Fn(&IpcFdEntry) -> bool,
{
    let entries = list_ipc_sock_pid_fds()?;
    Ok(entries.into_iter().filter(|entry| handler(entry)).collect())
}

/// Builds a fast lookup map from pid -> set of fd values that are unix `.sock`
/// descriptors, suitable for later filtering logic around BPF events.
pub fn ipc_fd_filter_map() -> Result<HashMap<u32, HashSet<i32>>> {
    let entries = list_ipc_sock_pid_fds()?;
    let mut map: HashMap<u32, HashSet<i32>> = HashMap::new();

    for entry in entries {
        map.entry(entry.pid).or_default().insert(entry.fd);
    }

    Ok(map)
}

/// Builds pid -> fd-set map for IPC unix sockets filtered by a caller-provided predicate.
///
/// Example: `ipc_fd_filter_map_filtered(|e| e.path.contains("mcp"))`
pub fn ipc_fd_filter_map_filtered<F>(handler: F) -> Result<HashMap<u32, HashSet<i32>>>
where
    F: Fn(&IpcFdEntry) -> bool,
{
    let entries = list_ipc_sock_pid_fds_filtered(handler)?;
    let mut map: HashMap<u32, HashSet<i32>> = HashMap::new();

    for entry in entries {
        map.entry(entry.pid).or_default().insert(entry.fd);
    }

    Ok(map)
}

/// Resolves the receiver process(es) given a sender's PID and FD.
/// Seamlessly finds the receiver for pipe-based streams (`pipe:[inode]`) and Unix sockets (`socket:[inode]`).
pub fn resolve_receiver(sender_pid: u32, sender_fd: u32) -> anyhow::Result<Vec<u32>> {
    let target_link = std::fs::read_link(format!("/proc/{}/fd/{}", sender_pid, sender_fd))?;
    let target_str = target_link.to_string_lossy();
    
    // We only process valid IPC types
    if !target_str.starts_with("pipe:[") && !target_str.starts_with("socket:[") {
        return Ok(vec![]);
    }

    let mut receivers = Vec::new();

    if target_str.starts_with("socket:[") {
        // Unix sockets have distinct inodes for each end, so a simple /proc scan won't find the peer.
        // We can use the system `ss` tool to get the peer process id associated with this inode.
        let inode_str = &target_str[8..target_str.len() - 1];
        if let Ok(inode) = inode_str.parse::<u64>() {
            if let Ok(output) = std::process::Command::new("ss").args(["-x", "-p"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    // Look for the line containing our inode
                    if line.contains(inode_str) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        for p in parts {
                            if p.starts_with("users:((") {
                                // Extract pid from string like `users:(("python3",pid=102384,fd=3))`
                                if let Some(pid_idx) = p.find("pid=") {
                                    let end_idx = p[pid_idx..].find(',').unwrap_or(p.len() - pid_idx);
                                    let pid_str = &p[pid_idx + 4 .. pid_idx + end_idx];
                                    if let Ok(pid) = pid_str.parse::<u32>() {
                                        if pid != sender_pid {
                                            receivers.push(pid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        receivers.sort();
        receivers.dedup();
        return Ok(receivers);
    }

    // Fallback: This is a pipe (`pipe:[...]`) which shares the exact same inode.
    // Scan all processes in /proc
    for entry in std::fs::read_dir("/proc")? {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        
        // Parse PID from folder name
        let pid_str = entry.file_name();
        let pid: u32 = match pid_str.to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Skip the sender process itself
        if pid == sender_pid { continue; }

        let fd_dir = entry.path().join("fd");
        let fd_entries = match std::fs::read_dir(&fd_dir) {
            Ok(iter) => iter,
            Err(_) => continue,
        };

        // Check FDs of this particular process
        for fd_entry in fd_entries {
            let fd_entry = match fd_entry { Ok(e) => e, Err(_) => continue };
            
            if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                if link.to_string_lossy() == target_str {
                    receivers.push(pid);
                    break; // Move to the next process since we found a match here
                }
            }
        }
    }

    receivers.sort();
    receivers.dedup();
    
    Ok(receivers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_stat_self() {
        let pid = std::process::id();
        let stat = get_stat(pid).expect("Should be able to get stat for self");
        assert!(stat.starttime > 0, "Starttime should be positive");
    }

    #[test]
    fn test_get_stat_nonexistent() {
        // PID 0 is usually not valid, or we can use a very large PID
        let res = get_stat(9999999);
        assert!(res.is_err(), "Should fail for nonexistent PID");
    }

    #[test]
    fn test_get_process_type_self() {
        let pid = std::process::id();
        let ptype = get_process_type(pid).expect("Should be able to get process type for self");
        // Our test runner is an ELF binary.
        assert_eq!(ptype, ProcessType::ElfBinary);
    }

    #[test]
    fn test_get_cmdline_self() {
        let pid = std::process::id();
        let cmdline = get_cmdline(pid).expect("Should be able to get cmdline for self");
        assert!(!cmdline.is_empty(), "Cmdline should not be empty for self");
        // The first argument is usually the executable name.
        assert!(cmdline[0].contains("aidt") || cmdline[0].contains("cargo"), "First arg should contain program name");
    }

    #[test]
    fn test_get_mapped_files_self() {
        let pid = std::process::id();
        let maps = get_mapped_files(pid).expect("Should be able to get maps for self");
        assert!(!maps.is_empty(), "Maps should not be empty for self");
        // Should contain at least one shared library or the executable itself
        assert!(maps.iter().any(|m| m.contains("libc") || m.contains("aidt")), "Maps should contain libc or aidt");
    }

    #[test]
    fn test_parse_proc_net_unix_line() {
        let line = "ffff8d8b3dd9e400: 00000002 00000000 00010000 0001 01 89928 /tmp/mcp-KUuNbI/mcp.sock";
        let parsed = parse_proc_net_unix_line(line).expect("line should parse");
        assert_eq!(parsed.inode, 89928);
        assert_eq!(parsed.path, "/tmp/mcp-KUuNbI/mcp.sock");
    }

    #[test]
    fn test_parse_proc_net_unix_line_skips_non_sock() {
        let line = "ffff8d8b2d49b400: 00000003 00000000 00000000 0001 03 23013 /run/user/52620/bus";
        assert!(parse_proc_net_unix_line(line).is_none());
    }
}
