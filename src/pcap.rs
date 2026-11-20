//! Minimal libpcap/Npcap binding, loaded at *runtime*.
//!
//! The library (`wpcap.dll` on Windows, `libpcap` elsewhere) is opened on
//! first use (`Device::list()`), not linked at build time. Everything that
//! doesn't capture or inject raw frames - pings, DNS queries,
//! the interface list - therefore runs on a machine without Npcap, and the
//! L2 side reports "Npcap/libpcap not found" through the normal error
//! path. It also means no Npcap SDK / import library is needed to build.
//!
//! Only the small API surface the app uses is provided, shaped like the
//! `pcap` crate's (`Device`, `Capture<Inactive/Active>`,
//! `Error::{PcapError, TimeoutExpired, LoadError}`).
//!
//! The Npcap *driver* cannot be embedded; on Windows it has to be
//! installed for L2 features to work.

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_uint, c_void};
use std::fmt;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::sync::OnceLock;

// ---------------------------------------------------------------- errors

#[derive(Debug)]
pub enum Error {
    /// libpcap reported an error (message from `pcap_geterr`/`errbuf`).
    PcapError(String),
    /// A read timed out without a packet - not a failure, just "try again".
    TimeoutExpired,
    /// The pcap library itself couldn't be loaded (not installed).
    LoadError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PcapError(m) => write!(f, "{m}"),
            Error::TimeoutExpired => write!(f, "timeout expired"),
            Error::LoadError(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

// ------------------------------------------------------- dynamic library

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut PcapAddr,
    flags: c_uint,
}

#[repr(C)]
struct PcapAddr {
    next: *mut PcapAddr,
    addr: *mut c_void, // struct sockaddr *
    netmask: *mut c_void,
    broadaddr: *mut c_void,
    dstaddr: *mut c_void,
}

/// `struct pcap_pkthdr`; `timeval` is `{long, long}` on every platform we
/// target (LLP64 Windows: two i32; LP64 Linux/macOS: two 8-byte fields).
#[repr(C)]
struct PktHdr {
    ts_sec: c_long,
    ts_usec: c_long,
    caplen: c_uint,
    len: c_uint,
}

#[repr(C)]
struct BpfProgram {
    bf_len: c_uint,
    bf_insns: *mut c_void,
}

type PcapT = c_void;

struct Api {
    // Keeps the library mapped for the lifetime of the process; the function
    // pointers below are only valid while it is. Never dropped (`static`).
    _lib: libloading::Library,
    findalldevs: unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int,
    freealldevs: unsafe extern "C" fn(*mut PcapIf),
    create: unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut PcapT,
    set_snaplen: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
    set_promisc: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
    set_timeout: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
    /// Absent in very old libpcap; then simply not applied.
    set_immediate_mode: Option<unsafe extern "C" fn(*mut PcapT, c_int) -> c_int>,
    activate: unsafe extern "C" fn(*mut PcapT) -> c_int,
    close: unsafe extern "C" fn(*mut PcapT),
    geterr: unsafe extern "C" fn(*mut PcapT) -> *mut c_char,
    statustostr: unsafe extern "C" fn(c_int) -> *const c_char,
    next_ex: unsafe extern "C" fn(*mut PcapT, *mut *mut PktHdr, *mut *const u8) -> c_int,
    sendpacket: unsafe extern "C" fn(*mut PcapT, *const u8, c_int) -> c_int,
    compile: unsafe extern "C" fn(*mut PcapT, *mut BpfProgram, *const c_char, c_int, c_uint) -> c_int,
    setfilter: unsafe extern "C" fn(*mut PcapT, *mut BpfProgram) -> c_int,
    freecode: unsafe extern "C" fn(*mut BpfProgram),
}

fn library_candidates() -> Vec<String> {
    #[cfg(windows)]
    {
        // Npcap's default (non-WinPcap-compatible) install lives in
        // System32\Npcap; the compat mode / WinPcap puts wpcap.dll straight
        // in System32, which a plain `wpcap.dll` lookup finds.
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
        vec![format!("{root}\\System32\\Npcap\\wpcap.dll"), "wpcap.dll".to_owned()]
    }
    #[cfg(target_os = "macos")]
    {
        vec!["libpcap.A.dylib".to_owned(), "libpcap.dylib".to_owned()]
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        vec![
            "libpcap.so.1".to_owned(),
            "libpcap.so.0.8".to_owned(),
            "libpcap.so".to_owned(),
        ]
    }
}

fn open_library(name: &str) -> Result<libloading::Library, libloading::Error> {
    #[cfg(windows)]
    {
        // wpcap.dll depends on Packet.dll next to it - for a full path, make
        // Windows resolve dependencies from the DLL's own directory.
        if name.contains('\\') {
            use libloading::os::windows::{LOAD_WITH_ALTERED_SEARCH_PATH, Library};
            return unsafe { Library::load_with_flags(name, LOAD_WITH_ALTERED_SEARCH_PATH) }
                .map(Into::into);
        }
    }
    unsafe { libloading::Library::new(name) }
}

fn load_api() -> Result<Api, String> {
    let mut tried = Vec::new();
    let mut lib = None;
    for name in library_candidates() {
        match open_library(&name) {
            Ok(l) => {
                lib = Some(l);
                break;
            }
            Err(e) => tried.push(format!("{name}: {e}")),
        }
    }
    let Some(lib) = lib else {
        return Err(format!(
            "{} not found ({}). L2 features need Npcap (Windows, https://npcap.com) or libpcap (Linux).",
            if cfg!(windows) { "Npcap (wpcap.dll)" } else { "libpcap" },
            tried.join("; ")
        ));
    };

    macro_rules! sym {
        ($name:literal) => {
            unsafe {
                *lib.get(concat!($name, "\0").as_bytes())
                    .map_err(|e| format!("{} missing in pcap library: {e}", $name))?
            }
        };
    }
    macro_rules! sym_opt {
        ($name:literal) => {
            unsafe { lib.get(concat!($name, "\0").as_bytes()).ok().map(|s| *s) }
        };
    }

    Ok(Api {
        findalldevs: sym!("pcap_findalldevs"),
        freealldevs: sym!("pcap_freealldevs"),
        create: sym!("pcap_create"),
        set_snaplen: sym!("pcap_set_snaplen"),
        set_promisc: sym!("pcap_set_promisc"),
        set_timeout: sym!("pcap_set_timeout"),
        set_immediate_mode: sym_opt!("pcap_set_immediate_mode"),
        activate: sym!("pcap_activate"),
        close: sym!("pcap_close"),
        geterr: sym!("pcap_geterr"),
        statustostr: sym!("pcap_statustostr"),
        next_ex: sym!("pcap_next_ex"),
        sendpacket: sym!("pcap_sendpacket"),
        compile: sym!("pcap_compile"),
        setfilter: sym!("pcap_setfilter"),
        freecode: sym!("pcap_freecode"),
        _lib: lib,
    })
}

/// Loaded on first use, then cached (including a failure, so a missing
/// library isn't re-probed on every call).
fn api() -> Result<&'static Api, Error> {
    static API: OnceLock<Result<Api, String>> = OnceLock::new();
    API.get_or_init(load_api)
        .as_ref()
        .map_err(|e| Error::LoadError(e.clone()))
}

// --------------------------------------------------------------- devices

const PCAP_IF_LOOPBACK: c_uint = 0x1;
const ERRBUF_SIZE: usize = 256;

#[derive(Debug, Clone, Copy)]
pub struct IfFlags(c_uint);

impl IfFlags {
    pub fn is_loopback(&self) -> bool {
        self.0 & PCAP_IF_LOOPBACK != 0
    }
}

#[derive(Debug, Clone)]
pub struct Address {
    pub addr: IpAddr,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub name: String,
    #[allow(dead_code)]
    pub description: Option<String>,
    pub addresses: Vec<Address>,
    pub flags: IfFlags,
}

/// Reads an IPv4/IPv6 address out of a `struct sockaddr *`; `None` for
/// other families (link-layer addresses etc.).
unsafe fn sockaddr_to_ip(sa: *const c_void) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    let p = sa as *const u8;

    // BSD/macOS: { u8 sa_len; u8 sa_family; ... }. Others: { u16 sa_family; ... }.
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    let family = unsafe { *p.add(1) } as u16;
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
    let family = unsafe { ptr::read_unaligned(p as *const u16) };

    const AF_INET: u16 = 2;
    #[cfg(windows)]
    const AF_INET6: u16 = 23;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const AF_INET6: u16 = 30;
    #[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
    const AF_INET6: u16 = 28; // FreeBSD; NetBSD/OpenBSD use 24 - unverified, unused by this app
    #[cfg(not(any(windows, target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd")))]
    const AF_INET6: u16 = 10; // Linux

    if family == AF_INET {
        // sockaddr_in: family(2) port(2) addr(4)
        let mut o = [0u8; 4];
        unsafe { ptr::copy_nonoverlapping(p.add(4), o.as_mut_ptr(), 4) };
        Some(IpAddr::V4(Ipv4Addr::from(o)))
    } else if family == AF_INET6 {
        // sockaddr_in6: family(2) port(2) flowinfo(4) addr(16) scope(4)
        let mut o = [0u8; 16];
        unsafe { ptr::copy_nonoverlapping(p.add(8), o.as_mut_ptr(), 16) };
        Some(IpAddr::V6(Ipv6Addr::from(o)))
    } else {
        None
    }
}

impl Device {
    /// All capture devices libpcap/Npcap knows about. Loads the library on
    /// first call; `Error::LoadError` if it isn't installed.
    pub fn list() -> Result<Vec<Device>, Error> {
        let api = api()?;
        let mut errbuf = [0 as c_char; ERRBUF_SIZE];
        let mut head: *mut PcapIf = ptr::null_mut();
        let rc = unsafe { (api.findalldevs)(&mut head, errbuf.as_mut_ptr()) };
        if rc != 0 {
            return Err(Error::PcapError(errbuf_to_string(&errbuf)));
        }

        let mut out = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            let d = unsafe { &*cur };
            let name = unsafe { cstr_to_string(d.name) }.unwrap_or_default();
            let description = unsafe { cstr_to_string(d.description) };
            let mut addresses = Vec::new();
            let mut a = d.addresses;
            while !a.is_null() {
                let ar = unsafe { &*a };
                if let Some(ip) = unsafe { sockaddr_to_ip(ar.addr) } {
                    addresses.push(Address { addr: ip });
                }
                a = ar.next;
            }
            out.push(Device {
                name,
                description,
                addresses,
                flags: IfFlags(d.flags),
            });
            cur = d.next;
        }
        if !head.is_null() {
            unsafe { (api.freealldevs)(head) };
        }
        Ok(out)
    }
}

unsafe fn cstr_to_string(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

fn errbuf_to_string(buf: &[c_char]) -> String {
    unsafe { cstr_to_string(buf.as_ptr()) }.unwrap_or_default()
}

// --------------------------------------------------------------- capture

/// Marker types for `Capture`'s state, as in the `pcap` crate.
pub struct Inactive;
pub struct Active;

pub struct Capture<S> {
    name: String,
    promisc: bool,
    snaplen: i32,
    timeout_ms: i32,
    immediate: bool,
    handle: *mut PcapT, // null while Inactive
    _state: PhantomData<S>,
}

// A pcap handle may be moved to another thread (used from one at a time),
// just not shared - same guarantees as the `pcap` crate gives.
unsafe impl Send for Capture<Active> {}

pub struct Packet<'a> {
    pub data: &'a [u8],
}

impl Capture<Inactive> {
    pub fn from_device(device: Device) -> Result<Capture<Inactive>, Error> {
        api()?; // fail early, with the "not installed" message, if unavailable
        Ok(Capture {
            name: device.name,
            promisc: false,
            snaplen: 65535,
            timeout_ms: 0,
            immediate: false,
            handle: ptr::null_mut(),
            _state: PhantomData,
        })
    }

    pub fn promisc(mut self, on: bool) -> Self {
        self.promisc = on;
        self
    }

    pub fn snaplen(mut self, n: i32) -> Self {
        self.snaplen = n;
        self
    }

    pub fn timeout(mut self, ms: i32) -> Self {
        self.timeout_ms = ms;
        self
    }

    pub fn immediate_mode(mut self, on: bool) -> Self {
        self.immediate = on;
        self
    }

    pub fn open(self) -> Result<Capture<Active>, Error> {
        let api = api()?;
        let cname = CString::new(self.name.as_str())
            .map_err(|_| Error::PcapError("device name contains a NUL byte".to_owned()))?;
        let mut errbuf = [0 as c_char; ERRBUF_SIZE];
        let h = unsafe { (api.create)(cname.as_ptr(), errbuf.as_mut_ptr()) };
        if h.is_null() {
            return Err(Error::PcapError(errbuf_to_string(&errbuf)));
        }

        unsafe {
            (api.set_snaplen)(h, self.snaplen);
            (api.set_promisc)(h, self.promisc as c_int);
            (api.set_timeout)(h, self.timeout_ms);
            if self.immediate {
                if let Some(f) = api.set_immediate_mode {
                    f(h, 1);
                }
            }
        }

        let rc = unsafe { (api.activate)(h) };
        if rc < 0 {
            // Prefer the handle's own message (e.g. "Operation not permitted"),
            // fall back to the generic status text.
            let detail = unsafe { cstr_to_string((api.geterr)(h)) }.filter(|s| !s.is_empty());
            let status = unsafe { cstr_to_string((api.statustostr)(rc)) }.unwrap_or_default();
            unsafe { (api.close)(h) };
            return Err(Error::PcapError(match detail {
                Some(d) if !status.is_empty() => format!("{status}: {d}"),
                Some(d) => d,
                None => status,
            }));
        }
        // rc > 0 is a warning (e.g. promiscuous mode not supported); the
        // handle is usable, same as the `pcap` crate treats it.

        Ok(Capture {
            name: self.name.clone(),
            promisc: self.promisc,
            snaplen: self.snaplen,
            timeout_ms: self.timeout_ms,
            immediate: self.immediate,
            handle: h,
            _state: PhantomData,
        })
    }
}

impl Capture<Active> {
    fn last_error(&self) -> String {
        match api() {
            Ok(api) => unsafe { cstr_to_string((api.geterr)(self.handle)) }.unwrap_or_default(),
            Err(e) => e.to_string(),
        }
    }

    /// Next captured frame. `Err(TimeoutExpired)` when the read timeout
    /// elapsed without one. The returned slice is valid until the next call.
    pub fn next_packet(&mut self) -> Result<Packet<'_>, Error> {
        let api = api()?;
        let mut hdr: *mut PktHdr = ptr::null_mut();
        let mut data: *const u8 = ptr::null();
        let rc = unsafe { (api.next_ex)(self.handle, &mut hdr, &mut data) };
        match rc {
            1 if !hdr.is_null() && !data.is_null() => {
                let len = unsafe { (*hdr).caplen } as usize;
                Ok(Packet {
                    data: unsafe { std::slice::from_raw_parts(data, len) },
                })
            }
            0 => Err(Error::TimeoutExpired),
            -2 => Err(Error::PcapError("end of capture".to_owned())),
            _ => Err(Error::PcapError(self.last_error())),
        }
    }

    pub fn sendpacket(&mut self, buf: impl AsRef<[u8]>) -> Result<(), Error> {
        let api = api()?;
        let buf = buf.as_ref();
        let rc = unsafe { (api.sendpacket)(self.handle, buf.as_ptr(), buf.len() as c_int) };
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::PcapError(self.last_error()))
        }
    }

    /// Install a BPF capture filter (tcpdump syntax).
    pub fn filter(&mut self, program: &str, optimize: bool) -> Result<(), Error> {
        let api = api()?;
        let c = CString::new(program)
            .map_err(|_| Error::PcapError("filter contains a NUL byte".to_owned()))?;
        let mut prog = BpfProgram {
            bf_len: 0,
            bf_insns: ptr::null_mut(),
        };
        // 0xffffffff = PCAP_NETMASK_UNKNOWN
        let rc = unsafe { (api.compile)(self.handle, &mut prog, c.as_ptr(), optimize as c_int, 0xffff_ffff) };
        if rc != 0 {
            return Err(Error::PcapError(self.last_error()));
        }
        let rc = unsafe { (api.setfilter)(self.handle, &mut prog) };
        let result = if rc == 0 {
            Ok(())
        } else {
            Err(Error::PcapError(self.last_error()))
        };
        unsafe { (api.freecode)(&mut prog) };
        result
    }
}

impl<S> Drop for Capture<S> {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            if let Ok(api) = api() {
                unsafe { (api.close)(self.handle) };
            }
            self.handle = ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_devices_and_finds_loopback() {
        match Device::list() {
            Ok(devs) => {
                assert!(!devs.is_empty());
                assert!(devs.iter().any(|d| d.flags.is_loopback()), "{devs:?}");
            }
            // Library not installed on the test machine: must be the clean error.
            Err(e) => assert!(matches!(e, Error::LoadError(_)), "{e}"),
        }
    }

    /// Loopback capture + injection round trip (skipped without privileges
    /// or without libpcap).
    #[test]
    fn loopback_inject_and_capture() {
        let Ok(devs) = Device::list() else { return };
        let Some(lo) = devs.into_iter().find(|d| d.flags.is_loopback()) else { return };
        let Ok(mut cap) = Capture::from_device(lo)
            .unwrap()
            .promisc(true)
            .snaplen(65535)
            .immediate_mode(true)
            .timeout(100)
            .open()
        else {
            eprintln!("skipped: cannot open loopback (no privileges)");
            return;
        };
        cap.filter("udp and port 54321", true).unwrap();

        // Send a real UDP datagram over loopback and see it on the wire.
        let a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..5 {
            a.send_to(b"statorius", "127.0.0.1:54321").unwrap();
        }
        let mut seen = false;
        for _ in 0..30 {
            match cap.next_packet() {
                Ok(p) => {
                    if p.data.windows(9).any(|w| w == b"statorius") {
                        seen = true;
                        break;
                    }
                }
                Err(Error::TimeoutExpired) => {}
                Err(e) => panic!("{e}"),
            }
        }
        assert!(seen, "did not capture the loopback datagram");
    }
}
