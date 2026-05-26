use std::net::Ipv4Addr;

#[repr(u32)]
#[derive(Debug)]
#[allow(dead_code)]
pub enum AidtEventType {
    ProcessExec = 0,
    ProcessExit = 1,
    Connection = 2,
    Sni = 3,
    MCPCall = 4,
    HttpSse = 5,
}

#[repr(C)]
pub struct AidtEvent {
    pub event_type: AidtEventType,
    pub len: u32,
    pub msg: [u8; 0],
}

#[repr(C)]
pub struct AidtProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub tgid: u32,
    pub cookie: u64,
    pub comm: [i8; 16],
}

#[repr(C)]
pub struct AidtConnectionEvent {
    pub pid: u32,
    pub cookie: u64,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub direction: u8,
    _pad: u8, // padding for alignment if needed
}

#[repr(C)]
pub struct AidtSniEvent {
    pub pid: u32,
    pub cookie: u64,
    pub sni: [u8; 64],
}

#[repr(C)]
pub struct AidtMCPCallEvent {
    pub pid: u32,
    pub tgid: u32,
    pub cookie: u64,
    pub fd: u32,
}

#[repr(C)]
pub struct AidtHttpSseEvent {
    pub pid: u32,
    pub tgid: u32,
    pub cookie: u64,
    pub fd: u32,
    pub direction: u8,
    pub _pad: [u8; 3],
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub _pad2: u16,
    pub payload_snippet: [u8; 256],
}

pub fn handle_event(data: &[u8]) -> i32 {
    if data.len() < std::mem::size_of::<AidtEvent>() {
        return 0;
    }

    let header = unsafe { &*(data.as_ptr() as *const AidtEvent) };
    let payload_ptr = unsafe { data.as_ptr().add(std::mem::size_of::<AidtEvent>()) };

    match header.event_type {
        AidtEventType::ProcessExec => {
            if data.len() < std::mem::size_of::<AidtEvent>() + std::mem::size_of::<AidtProcessEvent>() {
                return 0;
            }
            let pe = unsafe { &*(payload_ptr as *const AidtProcessEvent) };
            let comm = unsafe { std::ffi::CStr::from_ptr(pe.comm.as_ptr()).to_string_lossy() };            

            log::info!(
                "[{:?}] PID: {}, TGID: {}, PPID: {}, Comm: {}",
                header.event_type,
                pe.pid,
                pe.tgid,
                pe.ppid,
                comm
            );
        }
        AidtEventType::ProcessExit => {
            if data.len() < std::mem::size_of::<AidtEvent>() + std::mem::size_of::<AidtProcessEvent>() {
                return 0;
            }
            let pe = unsafe { &*(payload_ptr as *const AidtProcessEvent) };
            let comm = unsafe { std::ffi::CStr::from_ptr(pe.comm.as_ptr()).to_string_lossy() };
            
            log::info!(
                "[{:?}] PID: {}, TGID: {}, PPID: {}, Comm: {}",
                header.event_type,
                pe.pid,
                pe.tgid,
                pe.ppid,
                comm
            );
        }
        AidtEventType::Connection => {
            if data.len() < std::mem::size_of::<AidtEvent>() + std::mem::size_of::<AidtConnectionEvent>() {
                return 0;
            }
            let ce = unsafe { &*(payload_ptr as *const AidtConnectionEvent) };
            
            let saddr = Ipv4Addr::from(u32::from_be(ce.saddr));
            let daddr = Ipv4Addr::from(u32::from_be(ce.daddr));
            let dir_str = if ce.direction == 0 { "OUT" } else { "IN" };

            log::info!(
                "[Connection {}] PID: {}, Cookie: {}, {}:{} -> {}:{}",
                dir_str,
                ce.pid,
                ce.cookie,
                saddr,
                u16::from_be(ce.sport),
                daddr,
                u16::from_be(ce.dport)
            );
        }
        AidtEventType::Sni => {
            if data.len() < std::mem::size_of::<AidtEvent>() + std::mem::size_of::<AidtSniEvent>() {
                return 0;
            }
            let se = unsafe { &*(payload_ptr as *const AidtSniEvent) };
            let sni_str = String::from_utf8_lossy(&se.sni).trim_end_matches('\0').to_string();

            log::info!(
                "[SNI] PID: {}, SNI: {}",
                se.pid,
                sni_str
            );
        }
        AidtEventType::MCPCall => {
            if data.len() < std::mem::size_of::<AidtEvent>() + std::mem::size_of::<AidtMCPCallEvent>() {
                return 0;
            }
            let ae = unsafe { &*(payload_ptr as *const AidtMCPCallEvent) };
            
            // Resolve the receiver of this tool call invocation
            let receivers = crate::proc::resolve_receiver(ae.pid, ae.fd).unwrap_or_default();
            
            log::info!("[MCP_CALL Sender] PID: {}, TGID: {}, Cookie: {}, Target FD: {}, Receiver PIDs: {:?}", ae.pid, ae.tgid, ae.cookie, ae.fd, receivers);
        }
        AidtEventType::HttpSse => {
            if data.len() < std::mem::size_of::<AidtEvent>() + std::mem::size_of::<AidtHttpSseEvent>() {
                return 0;
            }
            let he = unsafe { &*(payload_ptr as *const AidtHttpSseEvent) };
            let snippet = String::from_utf8_lossy(&he.payload_snippet).trim_end_matches('\0').to_string();
            let dir_str = if he.direction == 0 { "OUT" } else { "IN" };
            let saddr = Ipv4Addr::from(u32::from_be(he.saddr));
            let daddr = Ipv4Addr::from(u32::from_be(he.daddr));
            
            log::info!("[HTTP/SSE {}] PID: {}, TGID: {}, {}:{} -> {}:{}, Payload: {}", 
                dir_str, he.pid, he.tgid,
                saddr, he.sport, daddr, u16::from_be(he.dport),
                snippet.escape_debug());
        }
    }

    0
}
