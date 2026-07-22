//! VeraCrypt `get_argon2_params` — PIM → Argon2id time/memory.
//! Source of truth: vendor/VeraCrypt/src/Common/Pkcs5.c

use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// Time cost (iterations).
    pub time_cost: u32,
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Parallelism (VeraCrypt uses 1 for header derivation).
    pub parallelism: u32,
}

impl Drop for Argon2Params {
    fn drop(&mut self) {
        self.time_cost.zeroize();
        self.memory_kib.zeroize();
        self.parallelism.zeroize();
    }
}

/// Map VeraCrypt PIM to Argon2id parameters.
/// `pim == 0` means default PIM 12.
pub fn argon2_params_for_pim(pim: i32) -> Argon2Params {
    let mut pim = pim;
    if pim < 0 {
        pim = 0;
    }
    if pim == 0 {
        pim = 12;
    }

    let mut m_cost_mib = 64 + (pim - 1) * 32;
    if m_cost_mib > 1024 {
        m_cost_mib = 1024;
    }
    let memory_kib = (m_cost_mib as u32).saturating_mul(1024);

    let time_cost = if pim <= 31 {
        3 + ((pim - 1) / 3)
    } else {
        13 + (pim - 31)
    } as u32;

    Argon2Params {
        time_cost,
        memory_kib,
        parallelism: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pim_12() {
        let p = argon2_params_for_pim(0);
        assert_eq!(p.time_cost, 6);
        assert_eq!(p.memory_kib, 416 * 1024);
    }

    #[test]
    fn pim_31_caps_memory() {
        let p = argon2_params_for_pim(31);
        assert_eq!(p.memory_kib, 1024 * 1024);
        assert_eq!(p.time_cost, 13);
    }

    #[test]
    fn pim_32_increases_time() {
        let p = argon2_params_for_pim(32);
        assert_eq!(p.memory_kib, 1024 * 1024);
        assert_eq!(p.time_cost, 14);
    }
}
