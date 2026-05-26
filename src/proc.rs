#![allow(dead_code)]

use anyhow::{Context, Result};
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
}
