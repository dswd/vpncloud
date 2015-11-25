use std::{mem, slice, ptr};

#[inline(always)]
pub unsafe fn as_bytes<T>(obj: &T) -> &[u8] {
    slice::from_raw_parts(mem::transmute::<&T, *const u8>(obj), mem::size_of::<T>())
}

#[inline(always)]
pub unsafe fn as_obj<T>(data: &[u8]) -> &T {
    assert!(data.len() >= mem::size_of::<T>());
    mem::transmute(data.as_ptr())
}

pub fn to_vec(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(data.len());
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), v.as_mut_ptr(), data.len());
        v.set_len(data.len());
    }
    v
}

macro_rules! fail {
    ($format:expr) => ( {
        use std::process;
        error!($format);
        process::exit(-1);
    } );
    ($format:expr, $( $arg:expr ),+) => ( {
        use std::process;
        error!($format, $( $arg ),+ );
        process::exit(-1);
    } );
}

macro_rules! try_fail {
    ($val:expr, $format:expr) => ( {
        match $val {
            Ok(val) => val,
            Err(err) => fail!($format, err)
        }
    } );
    ($val:expr, $format:expr, $( $arg:expr ),+) => ( {
        match $val {
            Ok(val) => val,
            Err(err) => fail!($format, $( $arg ),+, err)
        }
    } );
}
