#![allow(deprecated)]
#![allow(clippy::inline_always)]

use core::{fmt::Debug, ptr};

use crate::address::Address;
use crate::fors::ForsParams;
use crate::hashes::HashSuite;
use crate::hypertree::HypertreeParams;
use crate::wots::WotsParams;
use crate::xmss::XmssParams;
use crate::{ParameterSet, PkSeed, SkPrf, SkSeed};
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use blake3::Hasher;
use const_oid::db::fips205; // placeholder OIDs for experiments
use hybrid_array::typenum::consts::{U16, U30, U32};
use hybrid_array::typenum::{U24, U34, U39, U42, U47, U49};
use hybrid_array::{Array, ArraySize};
use typenum::U;

const PAR_RAYON_BYTES: usize = 256 * 1024; // tune: 128–512 KiB are all reasonable
const COALESCE_CAP: usize = 64 * 1024; // buffer for many small parts

/// Copy slices into a fixed stack buffer (no bounds checks in the loop).
#[inline(always)]
fn memcpy_concat<const CAP: usize>(dst: &mut [u8; CAP], parts: &[&[u8]]) -> usize {
    let mut off = 0usize;
    // SAFETY: call sites ensure total_len <= CAP.
    for p in parts {
        let len = p.len();
        unsafe {
            ptr::copy_nonoverlapping(p.as_ptr(), dst.as_mut_ptr().add(off), len);
        }
        off += len;
    }
    off
}

#[inline(always)]
fn update_msg_parts_parallel(h: &mut blake3::Hasher, msg: &[&[impl AsRef<[u8]>]]) {
    let mut buf = Vec::with_capacity(COALESCE_CAP);
    let flush = |h: &mut blake3::Hasher, buf: &mut Vec<u8>| {
        if !buf.is_empty() {
            h.update(buf);
            buf.clear();
        }
    };

    for segs in msg.iter().copied().flatten() {
        let s = segs.as_ref();
        if s.len() >= PAR_RAYON_BYTES {
            flush(h, &mut buf);
            h.update_rayon(s); // parallel tree hashing on big slices
        } else {
            if buf.len() + s.len() > COALESCE_CAP {
                flush(h, &mut buf);
            }
            buf.extend_from_slice(s);
        }
    }
    flush(h, &mut buf);
}

#[inline(always)]
fn prf_msg_parallel_impl<N: ArraySize>(
    sk_prf: &[u8],
    opt_rand: &[u8],
    msg: &[&[impl AsRef<[u8]>]],
) -> Array<u8, N> {
    // Tiny fast path as before
    let mut total = sk_prf.len() + opt_rand.len();
    for segs in msg.iter().copied().flatten() {
        total += segs.as_ref().len();
    }
    if total <= 384 {
        let mut h = blake3::Hasher::new();
        let mut buf = [0u8; 384];
        let mut off = memcpy_concat::<384>(&mut buf, &[sk_prf, opt_rand]);
        for segs in msg.iter().copied().flatten() {
            let s = segs.as_ref();
            unsafe {
                core::ptr::copy_nonoverlapping(s.as_ptr(), buf.as_mut_ptr().add(off), s.len());
            }
            off += s.len();
        }
        h.update(&buf[..off]);
        let mut out = Array::<u8, N>::default();
        h.finalize_xof().fill(&mut out);
        return out;
    }

    // Parallel/streaming path
    let mut h = blake3::Hasher::new();
    h.update(sk_prf);
    h.update(opt_rand);
    update_msg_parts_parallel(&mut h, msg);
    let mut out = Array::<u8, N>::default();
    h.finalize_xof().fill(&mut out);
    out
}

#[inline(always)]
fn h_msg_parallel_impl<M: ArraySize>(
    rand: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[&[impl AsRef<[u8]>]],
) -> Array<u8, M> {
    let mut total = rand.len() + pk_seed.len() + pk_root.len();
    for segs in msg.iter().copied().flatten() {
        total += segs.as_ref().len();
    }
    if total <= 384 {
        let mut h = blake3::Hasher::new();
        let mut buf = [0u8; 384];
        let mut off = memcpy_concat::<384>(&mut buf, &[rand, pk_seed, pk_root]);
        for segs in msg.iter().copied().flatten() {
            let s = segs.as_ref();
            unsafe {
                core::ptr::copy_nonoverlapping(s.as_ptr(), buf.as_mut_ptr().add(off), s.len());
            }
            off += s.len();
        }
        h.update(&buf[..off]);
        let mut out = Array::<u8, M>::default();
        h.finalize_xof().fill(&mut out);
        return out;
    }

    let mut h = blake3::Hasher::new();
    h.update(rand);
    h.update(pk_seed);
    h.update(pk_root);
    update_msg_parts_parallel(&mut h, msg);
    let mut out = Array::<u8, M>::default();
    h.finalize_xof().fill(&mut out);
    out
}

#[inline(always)]
fn blake3_xof_into(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Hasher::new();

    // Tiny fast path: single update on stack buffer.
    let total: usize = parts.iter().map(|p| p.len()).sum();
    if total <= 384 {
        let mut buf = [0u8; 384];
        let used = memcpy_concat::<384>(&mut buf, parts);
        debug_assert_eq!(used, total);
        h.update(&buf[..used]);
    } else {
        for p in parts {
            h.update(p);
        }
    }

    h.finalize_xof().fill(out);
}

#[inline(always)]
fn xof_array<N: ArraySize>(parts: &[&[u8]]) -> Array<u8, N> {
    let mut out = Array::<u8, N>::default();
    blake3_xof_into(parts, &mut out);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// BLAKE3-based hash suite
pub struct Blake3<N, M> {
    _n: core::marker::PhantomData<N>,
    _m: core::marker::PhantomData<M>,
}

impl<N: ArraySize, M: ArraySize> HashSuite for Blake3<N, M>
where
    N: Debug + Clone + PartialEq + Eq,
    M: Debug + Clone + PartialEq + Eq,
{
    type N = N;
    type M = M;

    // prf_msg(sk_prf || opt_rand || msg_parts)
    #[inline(always)]
    fn prf_msg(
        sk_prf: &SkPrf<Self::N>,
        opt_rand: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::N> {
        prf_msg_parallel_impl::<Self::N>(sk_prf.as_ref(), opt_rand.as_slice(), msg)
        // // Flatten msg parts only if fits tiny path; else stream them after header.
        // let mut h = Hasher::new();
        // let hdr = [sk_prf.as_ref(), opt_rand.as_slice()];

        // // Compute total for fast-path decision.
        // let mut total = sk_prf.as_ref().len() + opt_rand.as_slice().len();
        // for segs in msg.iter().copied().flatten() {
        //     total += segs.as_ref().len();
        // }

        // if total <= 384 {
        //     let mut buf = [0u8; 384];
        //     let mut off = memcpy_concat::<384>(&mut buf, &hdr);
        //     for segs in msg.iter().copied().flatten() {
        //         let s = segs.as_ref();
        //         unsafe {
        //             ptr::copy_nonoverlapping(s.as_ptr(), buf.as_mut_ptr().add(off), s.len());
        //         }
        //         off += s.len();
        //     }
        //     h.update(&buf[..off]);
        //     let mut out = Array::<u8, Self::N>::default();
        //     h.finalize_xof().fill(&mut out);
        //     out
        // } else {
        //     for p in hdr {
        //         h.update(p);
        //     }
        //     for segs in msg.iter().copied().flatten() {
        //         h.update(segs.as_ref());
        //     }
        //     let mut out = Array::<u8, Self::N>::default();
        //     h.finalize_xof().fill(&mut out);
        //     out
        // }
    }

    // h_msg(rand || pk_seed || pk_root || msg_parts)
    #[inline(always)]
    fn h_msg(
        rand: &Array<u8, Self::N>,
        pk_seed: &PkSeed<Self::N>,
        pk_root: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::M> {
        h_msg_parallel_impl::<Self::M>(rand.as_slice(), pk_seed.as_ref(), pk_root.as_ref(), msg)
        // let mut h = Hasher::new();
        // let hdr = [rand.as_slice(), pk_seed.as_ref(), pk_root.as_ref()];

        // let mut total = rand.len() + pk_seed.as_ref().len() + pk_root.len();
        // for segs in msg.iter().copied().flatten() {
        //     total += segs.as_ref().len();
        // }

        // if total <= 384 {
        //     let mut buf = [0u8; 384];
        //     let mut off = memcpy_concat::<384>(&mut buf, &hdr);
        //     for segs in msg.iter().copied().flatten() {
        //         let s = segs.as_ref();
        //         unsafe {
        //             ptr::copy_nonoverlapping(s.as_ptr(), buf.as_mut_ptr().add(off), s.len());
        //         }
        //         off += s.len();
        //     }
        //     h.update(&buf[..off]);
        //     let mut out = Array::<u8, Self::M>::default();
        //     h.finalize_xof().fill(&mut out);
        //     out
        // } else {
        //     for p in hdr {
        //         h.update(p);
        //     }
        //     for segs in msg.iter().copied().flatten() {
        //         h.update(segs.as_ref());
        //     }
        //     let mut out = Array::<u8, Self::M>::default();
        //     h.finalize_xof().fill(&mut out);
        //     out
        // }
    }

    // prf_sk(pk_seed || adrs || sk_seed)
    #[inline(always)]
    fn prf_sk(
        pk_seed: &PkSeed<Self::N>,
        sk_seed: &SkSeed<Self::N>,
        adrs: &impl Address,
    ) -> Array<u8, Self::N> {
        xof_array::<Self::N>(&[pk_seed.as_ref(), adrs.as_ref(), sk_seed.as_ref()])
    }

    // t(pk_seed || adrs || m[0] || ... || m[L-1])  but avoid second copy of L*N
    #[inline(always)]
    fn t<L: ArraySize>(
        pk_seed: &PkSeed<Self::N>,
        adrs: &impl Address,
        m: &Array<Array<u8, Self::N>, L>,
    ) -> Array<u8, Self::N> {
        let mut h = Hasher::new();
        // 64 bytes prelude at most
        let mut buf = [0u8; 64];
        let used = memcpy_concat::<64>(&mut buf, &[pk_seed.as_ref(), adrs.as_ref()]);
        h.update(&buf[..used]);
        for i in 0..L::USIZE {
            h.update(m[i].as_slice());
        }
        let mut out = Array::<u8, Self::N>::default();
        h.finalize_xof().fill(&mut out);
        out
    }

    // h(pk_seed || adrs || m1 || m2)
    #[inline(always)]
    fn h(
        pk_seed: &PkSeed<Self::N>,
        adrs: &impl Address,
        m1: &Array<u8, Self::N>,
        m2: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        // 2N + header fits into 128 for N<=32
        xof_array::<Self::N>(&[
            pk_seed.as_ref(),
            adrs.as_ref(),
            m1.as_slice(),
            m2.as_slice(),
        ])
    }

    // f(pk_seed || adrs || m)
    #[inline(always)]
    fn f(
        pk_seed: &PkSeed<Self::N>,
        adrs: &impl Address,
        m: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        xof_array::<Self::N>(&[pk_seed.as_ref(), adrs.as_ref(), m.as_slice()])
    }
}

// --- Parameter sets: mirror SHAKE params. Names distinct; OIDs temporary.

/// 128s: small
pub type Blake3_128s = Blake3<U16, U30>;
impl WotsParams for Blake3_128s {
    type WotsMsgLen = U<32>;
    type WotsSigLen = U<35>;
}
impl XmssParams for Blake3_128s {
    type HPrime = U<9>;
}
impl HypertreeParams for Blake3_128s {
    type D = U<7>;
    type H = U<63>;
}
impl ForsParams for Blake3_128s {
    type K = U<14>;
    type A = U<12>;
    type MD = U<{ (12 * 14usize).div_ceil(8) }>;
}
impl ParameterSet for Blake3_128s {
    const NAME: &'static str = "SLH-DSA-BLAKE3-128s";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHAKE_128_S;
}

/// 128f: fast
pub type Blake3_128f = Blake3<U16, U34>;
impl WotsParams for Blake3_128f {
    type WotsMsgLen = U<32>;
    type WotsSigLen = U<35>;
}
impl XmssParams for Blake3_128f {
    type HPrime = U<3>;
}
impl HypertreeParams for Blake3_128f {
    type D = U<22>;
    type H = U<66>;
}
impl ForsParams for Blake3_128f {
    type K = U<33>;
    type A = U<6>;
    type MD = U<25>;
}
impl ParameterSet for Blake3_128f {
    const NAME: &'static str = "SLH-DSA-BLAKE3-128f";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHAKE_128_F;
}

/// 192s: small
pub type Blake3_192s = Blake3<U24, U39>;
impl WotsParams for Blake3_192s {
    type WotsMsgLen = U<{ 24 * 2 }>;
    type WotsSigLen = U<{ 24 * 2 + 3 }>;
}
impl XmssParams for Blake3_192s {
    type HPrime = U<9>;
}
impl HypertreeParams for Blake3_192s {
    type D = U<7>;
    type H = U<63>;
}
impl ForsParams for Blake3_192s {
    type K = U<17>;
    type A = U<14>;
    type MD = U<{ (14 * 17usize).div_ceil(8) }>;
}
impl ParameterSet for Blake3_192s {
    const NAME: &'static str = "SLH-DSA-BLAKE3-192s";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHAKE_192_S;
}

/// 192f: fast
pub type Blake3_192f = Blake3<U24, U42>;
impl WotsParams for Blake3_192f {
    type WotsMsgLen = U<{ 24 * 2 }>;
    type WotsSigLen = U<{ 24 * 2 + 3 }>;
}
impl XmssParams for Blake3_192f {
    type HPrime = U<3>;
}
impl HypertreeParams for Blake3_192f {
    type D = U<22>;
    type H = U<66>;
}
impl ForsParams for Blake3_192f {
    type K = U<33>;
    type A = U<8>;
    type MD = U<{ (33 * 8usize).div_ceil(8) }>;
}
impl ParameterSet for Blake3_192f {
    const NAME: &'static str = "SLH-DSA-BLAKE3-192f";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHAKE_192_F;
}

/// 256s: small
pub type Blake3_256s = Blake3<U32, U47>;
impl WotsParams for Blake3_256s {
    type WotsMsgLen = U<{ 32 * 2 }>;
    type WotsSigLen = U<{ 32 * 2 + 3 }>;
}
impl XmssParams for Blake3_256s {
    type HPrime = U<8>;
}
impl HypertreeParams for Blake3_256s {
    type D = U<8>;
    type H = U<64>;
}
impl ForsParams for Blake3_256s {
    type K = U<22>;
    type A = U<14>;
    type MD = U<{ (14 * 22usize).div_ceil(8) }>;
}
impl ParameterSet for Blake3_256s {
    const NAME: &'static str = "SLH-DSA-BLAKE3-256s";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHAKE_256_S;
}

/// 256f: fast
pub type Blake3_256f = Blake3<U32, U49>;
impl WotsParams for Blake3_256f {
    type WotsMsgLen = U<{ 32 * 2 }>;
    type WotsSigLen = U<{ 32 * 2 + 3 }>;
}
impl XmssParams for Blake3_256f {
    type HPrime = U<4>;
}
impl HypertreeParams for Blake3_256f {
    type D = U<17>;
    type H = U<68>;
}
impl ForsParams for Blake3_256f {
    type K = U<35>;
    type A = U<9>;
    type MD = U<{ (35 * 9usize).div_ceil(8) }>;
}
impl ParameterSet for Blake3_256f {
    const NAME: &'static str = "SLH-DSA-BLAKE3-256f";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHAKE_256_F;
}
