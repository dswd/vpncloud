use std::{mem, ptr, fmt};

use super::ethcloud::{Mac, Error};
use super::util::{as_bytes, as_obj};

#[derive(PartialEq)]
pub struct Frame<'a> {
    pub vlan: u16,
    pub src: &'a Mac,
    pub dst: &'a Mac,
    pub payload: &'a [u8]
}

impl<'a> fmt::Debug for Frame<'a> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(formatter, "src: {:?}, dst: {:?}, vlan: {}, payload: {} bytes",
            self.src, self.dst, self.vlan, self.payload.len())
    }
}

pub fn decode(data: &[u8]) -> Result<Frame, Error> {
    if data.len() < 14 {
        return Err(Error::ParseError("Frame is too short"));
    }
    let mut pos = 0;
    let dst = unsafe { as_obj::<Mac>(&data[pos..]) };
    pos += mem::size_of::<Mac>();
    let src = unsafe { as_obj::<Mac>(&data[pos..]) };
    pos += mem::size_of::<Mac>();
    let mut vlan = 0;
    let mut payload = &data[pos..];
    if data[pos] == 0x81 && data[pos+1] == 0x00 {
        pos += 2;
        if data.len() < pos + 2 {
            return Err(Error::ParseError("Vlan frame is too short"));
        }
        vlan = u16::from_be(* unsafe { as_obj::<u16>(&data[pos..]) });
        pos += 2;
        payload = &data[pos..];
    }
    Ok(Frame{vlan: vlan, src: src, dst: dst, payload: payload})
}

pub fn encode(frame: &Frame, buf: &mut [u8]) -> usize {
    assert!(buf.len() >= 16 + frame.payload.len());
    let mut pos = 0;
    unsafe {
        let dst_dat = as_bytes::<Mac>(frame.dst);
        ptr::copy_nonoverlapping(dst_dat.as_ptr(), buf[pos..].as_mut_ptr(), dst_dat.len());
        pos += dst_dat.len();
        let src_dat = as_bytes::<Mac>(frame.src);
        ptr::copy_nonoverlapping(src_dat.as_ptr(), buf[pos..].as_mut_ptr(), src_dat.len());
        pos += src_dat.len();
        if frame.vlan != 0 {
            buf[pos] = 0x81; buf[pos+1] = 0x00;
            pos += 2;
            let vlan_dat = mem::transmute::<u16, [u8; 2]>(frame.vlan.to_be());
            ptr::copy_nonoverlapping(vlan_dat.as_ptr(), buf[pos..].as_mut_ptr(), vlan_dat.len());
            pos += vlan_dat.len();
        }
        ptr::copy_nonoverlapping(frame.payload.as_ptr(), buf[pos..].as_mut_ptr(), frame.payload.len());
    }
    pos += frame.payload.len();
    pos
}


#[test]
fn without_vlan() {
    let src = Mac([1,2,3,4,5,6]);
    let dst = Mac([6,5,4,3,2,1]);
    let payload = [1,2,3,4,5,6,7,8];
    let mut buf = [0u8; 1024];
    let frame = Frame{src: &src, dst: &dst, vlan: 0, payload: &payload};
    let size = encode(&frame, &mut buf);
    assert_eq!(size, 20);
    assert_eq!(&buf[..size], &[6,5,4,3,2,1,1,2,3,4,5,6,1,2,3,4,5,6,7,8]);
    let frame2 = decode(&buf[..size]).unwrap();
    assert_eq!(frame, frame2);
}

#[test]
fn with_vlan() {
    let src = Mac([1,2,3,4,5,6]);
    let dst = Mac([6,5,4,3,2,1]);
    let payload = [1,2,3,4,5,6,7,8];
    let mut buf = [0u8; 1024];
    let frame = Frame{src: &src, dst: &dst, vlan: 1234, payload: &payload};
    let size = encode(&frame, &mut buf);
    assert_eq!(size, 24);
    assert_eq!(&buf[..size], &[6,5,4,3,2,1,1,2,3,4,5,6,0x81,0,4,210,1,2,3,4,5,6,7,8]);
    let frame2 = decode(&buf[..size]).unwrap();
    assert_eq!(frame, frame2);
}
