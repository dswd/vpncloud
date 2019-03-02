// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2019  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use libc;

use std::os::unix::io::RawFd;
use std::io;
use crate::device::Device;

use super::WaitResult;
use crate::device::Type;
use crate::net::Socket;

pub struct EpollWait {
    poll_fd: RawFd,
    event: libc::epoll_event,
    socketv4: RawFd,
    socketv6: RawFd,
    device: RawFd,
    timeout: u32,
}

impl EpollWait {
    pub fn new<S: Socket>(socketv4: &S, socketv6: &S, device: &Device, timeout: u32) -> io::Result<Self> {
        Self::create(socketv4, socketv6, device, timeout, libc::EPOLLIN as u32)
    }

    pub fn testing<S: Socket>(socketv4: &S, socketv6: &S, device: &Device, timeout: u32) -> io::Result<Self> {
        Self::create(socketv4, socketv6, device, timeout, ( libc::EPOLLIN | libc::EPOLLOUT ) as u32)
    }

    fn create<S: Socket>(socketv4: &S, socketv6: &S, device: &Device, timeout: u32, flags: u32) -> io::Result<Self> {
        let mut event = libc::epoll_event{u64: 0, events: 0};
        let poll_fd =  unsafe { libc::epoll_create(3) };
        if poll_fd == -1 {
            return Err(io::Error::last_os_error());
        }
        let raw_fds = if device.get_type() != Type::Dummy {
            vec![socketv4.as_raw_fd(), socketv6.as_raw_fd(), device.as_raw_fd()]
        } else {
            vec![socketv4.as_raw_fd(), socketv6.as_raw_fd()]
        };
        for fd in raw_fds {
            event.u64 = fd as u64;
            event.events = flags;
            let res = unsafe { libc::epoll_ctl(poll_fd, libc::EPOLL_CTL_ADD, fd, &mut event) };
            if res == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            poll_fd,
            event,
            socketv4: socketv4.as_raw_fd(),
            socketv6: socketv6.as_raw_fd(),
            device: device.as_raw_fd(),
            timeout
        })
    }
}

impl Drop for EpollWait {
    fn drop(&mut self) {
        unsafe { libc::close(self.poll_fd) };
    }
}

impl Iterator for EpollWait {
    type Item = WaitResult;

    fn next(&mut self) -> Option<Self::Item> {
        Some(match unsafe { libc::epoll_wait(self.poll_fd, &mut self.event, 1, self.timeout as i32) } {
            -1 => WaitResult::Error(io::Error::last_os_error()),
            0 => WaitResult::Timeout,
            1 => if self.event.u64 == self.socketv4 as u64 {
                WaitResult::SocketV4
            } else if self.event.u64 == self.socketv6 as u64 {
                WaitResult::SocketV6
            } else if self.event.u64 == self.device as u64 {
                WaitResult::Device
            } else {
                unreachable!()
            },
            _ => unreachable!()
        })
    }
}

