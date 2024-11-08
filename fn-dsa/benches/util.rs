use fn_dsa::{CryptoRng, RngCore, RngError};
use fn_dsa_comm::shake::{SHAKE256};

#[cfg(target_arch = "x86")]
pub fn core_cycles() -> u64 {
    use core::arch::x86::{_mm_lfence, _rdtsc};
    unsafe {
        _mm_lfence();
        _rdtsc()
    }
}

#[cfg(target_arch = "x86_64")]
pub fn core_cycles() -> u64 {
    use core::arch::x86_64::{_mm_lfence, _rdtsc};
    unsafe {
        _mm_lfence();
        _rdtsc()
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
pub fn core_cycles() -> u64 {
    use core::arch::asm;
    let mut x: u64;
    unsafe {
        asm!("dsb sy", "mrs {}, pmccntr_el0", out(reg) x);
    }
    x
}

#[cfg(target_arch = "riscv64")]
pub fn core_cycles() -> u64 {
    use core::arch::asm;
    let mut x: u64;
    unsafe {
        asm!("rdcycle {}", out(reg) x);
    }
    x
}

// Fake RNG for tests only; it is actually a wrapper around SHAKE256,
// initialized with a seed.
pub struct FakeRNG(SHAKE256);

impl FakeRNG {
    pub fn new(seed: &[u8]) -> Self {
        let mut sh = SHAKE256::new();
        sh.inject(seed);
        sh.flip();
        Self(sh)
    }
}

impl CryptoRng for FakeRNG {}
impl RngCore for FakeRNG {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.0.extract(&mut buf);
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.0.extract(&mut buf);
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.extract(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8])
        -> Result<(), RngError>
    {
        self.0.extract(dest);
        Ok(())
    }
}

pub fn banner_arch() {
    #[cfg(any(target_arch = "x86_64"))]
    println!("Arch: x86_64, AVX2:{}",
        if fn_dsa_comm::has_avx2() { "yes" } else { "no" });

    #[cfg(any(target_arch = "x86"))]
    println!("Arch: x86 (32-bit), AVX2:{}",
        if fn_dsa_comm::has_avx2() { "yes" } else { "no" });

    #[cfg(any(target_arch = "aarch64"))]
    println!("Arch: aarch64");

    #[cfg(any(target_arch = "arm64ec"))]
    println!("Arch: arm64ec");

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm64ec")))]
    println!("Arch: unknown");
}
