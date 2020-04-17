// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2019  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use crate::device::Device;
use std::{io, os::unix::io::RawFd};

use super::WaitResult;
use crate::{device::Type, net::Socket};

pub struct EpollWait {
    poll_fd: RawFd,
    event: libc::epoll_event,
    socket: RawFd,
    device: RawFd,
    timeout: u32
}

impl EpollWait {
    pub fn new<S: Socket>(socket: &S, device: &dyn Device, timeout: u32) -> io::Result<Self> {
        Self::create(socket, device, timeout, libc::EPOLLIN as u32)
    }

    pub fn testing<S: Socket>(socket: &S, device: &dyn Device, timeout: u32) -> io::Result<Self> {
        Self::create(socket, device, timeout, (libc::EPOLLIN | libc::EPOLLOUT) as u32)
    }

    fn create<S: Socket>(socket: &S, device: &dyn Device, timeout: u32, flags: u32) -> io::Result<Self> {
        let mut event = libc::epoll_event { u64: 0, events: 0 };
        let poll_fd = unsafe { libc::epoll_create(3) };
        if poll_fd == -1 {
            return Err(io::Error::last_os_error())
        }
        let raw_fds = if device.get_type() != Type::Dummy {
            vec![socket.as_raw_fd(), device.as_raw_fd()]
        } else {
            vec![socket.as_raw_fd()]
        };
        for fd in raw_fds {
            event.u64 = fd as u64;
            event.events = flags;
            let res = unsafe { libc::epoll_ctl(poll_fd, libc::EPOLL_CTL_ADD, fd, &mut event) };
            if res == -1 {
                return Err(io::Error::last_os_error())
            }
        }
        Ok(Self {
            poll_fd,
            event,
            socket: socket.as_raw_fd(),
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
            1 => {
                if self.event.u64 == self.socket as u64 {
                    WaitResult::Socket
                } else if self.event.u64 == self.device as u64 {
                    WaitResult::Device
                } else {
                    unreachable!()
                }
            }
            _ => unreachable!()
        })
    }
}
