use crate::platform::macos::sys::{in6_ifreq, siocgiflladdr, siocsiflladdr, IN6_IFF_NODAD};
use crate::platform::macos::tap::Tap;
use crate::platform::unix::device::ctl;
use crate::platform::unix::Tun;
use crate::platform::ETHER_ADDR_LEN;
use libc::{c_char, socklen_t, SYSPROTO_CONTROL, UTUN_OPT_IFNAME};
use std::ffi::{c_void, CStr};
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::{io, mem, ptr};
use std::sync::atomic::Ordering;

pub enum TunTap {
    Tun(Tun),
    Tap(Tap),
}

impl TunTap {
    pub fn name(&self) -> io::Result<String> {
        match &self {
            TunTap::Tun(tun) => {
                let mut tun_name = [0u8; 64];
                let mut name_len: socklen_t = 64;

                let optval = &mut tun_name as *mut _ as *mut c_void;
                let optlen = &mut name_len as *mut socklen_t;
                unsafe {
                    if libc::getsockopt(
                        tun.as_raw_fd(),
                        SYSPROTO_CONTROL,
                        UTUN_OPT_IFNAME,
                        optval,
                        optlen,
                    ) < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(CStr::from_ptr(tun_name.as_ptr() as *const c_char)
                        .to_string_lossy()
                        .into())
                }
            }
            TunTap::Tap(tap) => Ok(tap.name().to_string()),
        }
    }
    pub fn is_nonblocking(&self) -> io::Result<bool> {
        match &self {
            TunTap::Tun(tun) => tun.is_nonblocking(),
            TunTap::Tap(tap) => tap.is_nonblocking(),
        }
    }
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match &self {
            TunTap::Tun(tun) => tun.set_nonblocking(nonblocking),
            TunTap::Tap(tap) => tap.set_nonblocking(nonblocking),
        }
    }
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match &self {
            TunTap::Tun(tun) => tun.send(buf),
            TunTap::Tap(tap) => tap.send(buf),
        }
    }
    pub fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match &self {
            TunTap::Tun(tun) => tun.send_vectored(bufs),
            TunTap::Tap(tap) => tap.send_vectored(bufs),
        }
    }
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match &self {
            TunTap::Tun(tun) => tun.recv(buf),
            TunTap::Tap(tap) => tap.recv(buf),
        }
    }
    pub fn recv_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        match &self {
            TunTap::Tun(tun) => tun.recv_vectored(bufs),
            TunTap::Tap(tap) => tap.recv_vectored(bufs),
        }
    }
    pub fn request(&self) -> io::Result<libc::ifreq> {
        let tun_name = self.name()?;
        unsafe {
            let mut req: libc::ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(
                tun_name.as_ptr() as *const c_char,
                req.ifr_name.as_mut_ptr(),
                tun_name.len(),
            );
            Ok(req)
        }
    }
    pub fn request_v6(&self) -> io::Result<in6_ifreq> {
        let tun_name = self.name()?;
        unsafe {
            let mut req: in6_ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(
                tun_name.as_ptr() as *const c_char,
                req.ifra_name.as_mut_ptr(),
                tun_name.len(),
            );
            req.ifr_ifru.ifru_flags = IN6_IFF_NODAD as _;
            Ok(req)
        }
    }
    pub fn set_mac_address(&self, eth_addr: [u8; ETHER_ADDR_LEN as usize]) -> io::Result<()> {
        match &self {
            TunTap::Tun(_) => Err(io::Error::from(io::ErrorKind::Unsupported)),
            TunTap::Tap(_) => {
                let mut ifr = self.request()?;
                unsafe {
                    ifr.ifr_ifru.ifru_addr.sa_family = libc::AF_LINK as _;
                    ifr.ifr_ifru.ifru_addr.sa_len = ETHER_ADDR_LEN;
                    for (i, v) in eth_addr.iter().enumerate() {
                        ifr.ifr_ifru.ifru_addr.sa_data[i] = *v as _;
                    }
                    siocsiflladdr(ctl()?.inner, &mut ifr)?;
                }
                Ok(())
            }
        }
    }
    pub fn mac_address(&self) -> io::Result<[u8; ETHER_ADDR_LEN as usize]> {
        match &self {
            TunTap::Tun(_) => Err(io::Error::from(io::ErrorKind::Unsupported)),
            TunTap::Tap(_) => {
                let mut ifr = self.request()?;
                unsafe {
                    ifr.ifr_ifru.ifru_addr.sa_family = libc::AF_LINK as _;
                    ifr.ifr_ifru.ifru_addr.sa_len = ETHER_ADDR_LEN;

                    siocgiflladdr(ctl()?.inner, &mut ifr)?;
                    let mut eth_addr = [0; ETHER_ADDR_LEN as usize];
                    for (i, v) in eth_addr.iter_mut().enumerate() {
                        *v = ifr.ifr_ifru.ifru_addr.sa_data[i] as _;
                    }
                    Ok(eth_addr)
                }
            }
        }
    }
    #[inline]
    pub(crate) fn ignore_packet_info(&self) -> bool {
        match &self {
            TunTap::Tun(tun) => tun.ignore_packet_info(),
            TunTap::Tap(_) => {
                true
            }
        }
        
    }
    pub(crate) fn set_ignore_packet_info(&self, ign: bool) {
        match &self {
            TunTap::Tun(tun) => tun.set_ignore_packet_info(ign),
            TunTap::Tap(_) => {
            }
        }
    }
}
impl AsRawFd for TunTap {
    fn as_raw_fd(&self) -> RawFd {
        match &self {
            TunTap::Tun(tun) => tun.as_raw_fd(),
            TunTap::Tap(tap) => tap.as_raw_fd(),
        }
    }
}
impl IntoRawFd for TunTap {
    fn into_raw_fd(self) -> RawFd {
        match self {
            TunTap::Tun(tun) => tun.into_raw_fd(),
            TunTap::Tap(_tap) => {
                // tap not supported IntoRawFd
                -1
            }
        }
    }
}
