use libc;

use std::os::unix::io::RawFd;
use std::io;
use std::ops::{Deref, DerefMut};

bitflags!{
    pub flags Flags: u32 {
        const READ = libc::EPOLLIN as u32,
        const WRITE = libc::EPOLLOUT as u32,
        const ERROR = libc::EPOLLERR as u32,
    }
}

#[derive(Clone, Copy)]
pub struct Event(libc::epoll_event);

impl Event {
    #[inline]
    pub fn fd(&self) -> RawFd {
        self.0.u64 as RawFd
    }

    #[inline]
    pub fn flags(&self) -> Flags {
        Flags::from_bits(self.0.events).expect("Invalid flags set")
    }

    #[inline]
    fn new(fd: RawFd, flags: Flags) -> Self {
        Event(libc::epoll_event{u64: fd as u64, events: flags.bits})
    }
}

impl Deref for Event {
    type Target = libc::epoll_event;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Event {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}


pub struct Poll {
    fd: RawFd,
    events: Vec<Event>
}

impl Poll {
    #[inline]
    pub fn new(max_events: usize) -> io::Result<Self> {
        let mut events = Vec::with_capacity(max_events);
        events.resize(max_events, Event::new(0, Flags::empty()));
        let fd = unsafe { libc::epoll_create(max_events as i32) };
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(Poll{fd: fd, events: events})
    }

    #[inline]
    pub fn register(&mut self, fd: RawFd, flags: Flags) -> io::Result<()> {
        let mut ev = Event::new(fd, flags);
        let res = unsafe { libc::epoll_ctl(self.fd, libc::EPOLL_CTL_ADD, fd, &mut ev as &mut libc::epoll_event) };
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[inline]
    pub fn unregister(&mut self, fd: RawFd) -> io::Result<()> {
        let mut ev = Event::new(fd, Flags::empty());
        let res = unsafe { libc::epoll_ctl(self.fd, libc::EPOLL_CTL_DEL, fd, &mut ev as &mut libc::epoll_event) };
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[inline]
    pub fn wait(&mut self, timeout_millis: u32) -> io::Result<&[Event]> {
        let res = unsafe { libc::epoll_wait(self.fd, &mut self.events[0] as &mut libc::epoll_event, self.events.len() as i32, timeout_millis as i32) };
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(&self.events[0..res as usize])
    }
}

impl Drop for Poll {
    #[inline]
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}
