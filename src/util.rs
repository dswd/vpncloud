use std::{mem, slice};

#[inline(always)]
pub unsafe fn as_bytes<T>(obj: &T) -> &[u8] {
    slice::from_raw_parts(mem::transmute::<&T, *const u8>(obj), mem::size_of::<T>())
}

#[inline(always)]
pub unsafe fn as_obj<T>(data: &[u8]) -> &T {
    assert!(data.len() >= mem::size_of::<T>());
    mem::transmute(data.as_ptr())
}
