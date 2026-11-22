//! The one `--cpu` grammar, for both placements: `cw create`, `cw run`,
//! `cw resize`, the guided editors and presets take the same spellings and
//! refuse a bad one in the same words.

use anyhow::Context as _;

/// No environment has more than 256 CPUs.
const MAX_CPU_CORES: u64 = 256;

/// A local VM boots with whole vCPUs, from one through this many.
const LOCAL_VM_MAX_VCPUS: u32 = 32;

/// CPU is given in cores (`2`, `0.5`) or millicores with an `m` suffix
/// (`500m`). No environment has more than 256 CPUs, so a larger bare number
/// is a millicore value from before cores were the unit; it is refused with
/// the spelling that works instead of asking for thousands of CPUs.
pub(crate) fn parse_resize_cpu(value: &str) -> anyhow::Result<i32> {
    let value = value.trim();
    if let Ok(whole) = value.parse::<u64>()
        && whole > MAX_CPU_CORES
    {
        let suggestion = if whole % 1000 == 0 {
            (whole / 1000).to_string()
        } else {
            format!("{whole}m")
        };
        anyhow::bail!(
            "CPU is in cores, so {value} means {value} CPUs; use {suggestion}, or add m for millicores"
        );
    }
    if let Some(millicores) = value.strip_suffix('m') {
        let millicores: i32 = millicores
            .parse()
            .with_context(|| format!("invalid CPU quantity {value:?}"))?;
        if millicores <= 0 {
            anyhow::bail!("CPU must be greater than zero");
        }
        return Ok(millicores);
    }

    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (value, None),
    };
    if whole.is_empty() || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        anyhow::bail!("invalid CPU quantity {value:?}; use values such as 500m, 0.5, or 4");
    }
    let whole: i32 = whole
        .parse()
        .with_context(|| format!("invalid CPU quantity {value:?}"))?;
    let fractional_millicores = match fraction {
        None => 0,
        Some(fraction)
            if !fraction.is_empty()
                && fraction.len() <= 3
                && fraction.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            let scale = 10_i32.pow((3 - fraction.len()) as u32);
            let fraction: i32 = fraction
                .parse()
                .with_context(|| format!("invalid CPU quantity {value:?}"))?;
            fraction * scale
        }
        _ => anyhow::bail!(
            "invalid CPU quantity {value:?}; CPU fractions may have at most three decimal places"
        ),
    };
    let millicores = whole
        .checked_mul(1000)
        .and_then(|whole| whole.checked_add(fractional_millicores))
        .ok_or_else(|| anyhow::anyhow!("CPU quantity {value:?} is too large"))?;
    if millicores <= 0 {
        anyhow::bail!("CPU must be greater than zero");
    }
    Ok(millicores)
}

/// A local VM's vCPUs for a `--cpu` value, in the grammar above. A VM boots
/// with whole vCPUs, so a fraction (`0.5`, `1500m`) rounds up to the next
/// whole CPU: the VM never gets less than was asked for.
pub(crate) fn local_vm_vcpus(value: &str) -> anyhow::Result<u32> {
    // `parse_resize_cpu` refuses zero and below, so the value is positive.
    local_vm_vcpus_from_millicores(parse_resize_cpu(value)?.unsigned_abs())
}

/// A local VM's vCPUs for a CPU quantity in millicores, such as a
/// `codewire.yaml` `resources.cpu`, rounded up to whole CPUs as
/// [`local_vm_vcpus`] does.
pub(crate) fn local_vm_vcpus_from_millicores(millicores: u32) -> anyhow::Result<u32> {
    Some(millicores.div_ceil(1000))
        .filter(|vcpus| (1..=LOCAL_VM_MAX_VCPUS).contains(vcpus))
        .ok_or_else(|| anyhow::anyhow!("a local VM takes from 1 through {LOCAL_VM_MAX_VCPUS} CPUs"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_vm_takes_every_spelling_help_offers() {
        assert_eq!(local_vm_vcpus("2").unwrap(), 2);
        assert_eq!(local_vm_vcpus("0.5").unwrap(), 1);
        assert_eq!(local_vm_vcpus("500m").unwrap(), 1);
        assert_eq!(local_vm_vcpus("1.5").unwrap(), 2);
        assert_eq!(local_vm_vcpus("2000m").unwrap(), 2);
        assert_eq!(local_vm_vcpus("32").unwrap(), 32);
    }

    #[test]
    fn a_bad_cpu_value_is_refused_in_the_same_words_in_both_placements() {
        for value in ["lots", "1.2345", "0", "2000"] {
            let cloud = parse_resize_cpu(value).unwrap_err().to_string();
            let local = local_vm_vcpus(value).unwrap_err().to_string();
            assert_eq!(local, cloud, "{value}");
        }
        assert_eq!(
            local_vm_vcpus("lots").unwrap_err().to_string(),
            r#"invalid CPU quantity "lots"; use values such as 500m, 0.5, or 4"#
        );
    }

    #[test]
    fn a_local_vm_refuses_more_cpus_than_it_can_boot() {
        assert_eq!(
            local_vm_vcpus("33").unwrap_err().to_string(),
            "a local VM takes from 1 through 32 CPUs"
        );
        assert!(local_vm_vcpus_from_millicores(32_001).is_err());
    }
}
