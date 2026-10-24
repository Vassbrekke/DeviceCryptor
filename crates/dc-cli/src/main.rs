use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use dc_crypto::{
    bench_argon2id, bench_veracrypt_pim, fill_random, mlkem_decapsulate_key, mlkem_encapsulate_key,
    mlkem_generate_keypair, PrfId, WrappedKey,
};
use dc_format::dc01::{DC01_DEFAULT_MEM_KIB, DC01_DEFAULT_PARALLELISM, DC01_DEFAULT_TIME};
use dc_volume::{
    add_favorite, backup_headers, change_password, create_container, create_container_with_hidden,
    create_container_with_hidden_progress, create_container_with_progress, dismount_session,
    list_favorites, open_container, remove_favorite, restore_headers, inspect_header_backup,
    CreateOptions, Favorite,
    FsType, OpenOptions,
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "linux")]
use dc_volume::{format_volume, linux_dismount, linux_mount, load_mount_state, LinuxMountOptions};

#[derive(Parser, Debug)]
#[command(
    name = "dc",
    about = "DeviceCryptor — experimental encrypted containers (unaudited)",
    version,
    after_help = "Password tip: omit --password to type it silently. Prefer --password-env over --password (avoids argv leaks)."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new DC01 container
    Create {
        path: PathBuf,
        /// Total container size (bytes, or human: 16M, 1G, 512K)
        #[arg(long, default_value = "16M", value_parser = parse_size)]
        size: u64,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        keyfile: Vec<PathBuf>,
        /// Filesystem: fat32 (default, unprivileged mount) | ext4 (needs root to mount) | none
        #[arg(long, default_value = "fat32")]
        fs: String,
        #[arg(long, value_parser = parse_size)]
        hidden_size: Option<u64>,
        #[arg(long)]
        hidden_password: Option<String>,
        /// Fill data area with random (slow, more deniable)
        #[arg(long, default_value_t = false)]
        wipe: bool,
    },
    /// Mount a volume (Linux: FAT checkout to directory, or loop for ext4 as root)
    Mount {
        path: PathBuf,
        /// Mountpoint directory (created if missing; must be empty)
        mountpoint: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        password_env: Option<String>,
        #[arg(long)]
        keyfile: Vec<PathBuf>,
        #[arg(long, default_value_t = 0)]
        pim: i32,
        /// VeraCrypt PKCS-5 PRF: auto, sha512, sha256, blake2s, whirlpool, streebog, argon2
        #[arg(long, default_value = "auto")]
        prf: String,
        #[arg(long, default_value = "default")]
        id: String,
        #[arg(long, default_value = "auto")]
        fs: String,
        /// Protect hidden volume from outer-volume writes
        #[arg(long, default_value_t = false)]
        protect_hidden: bool,
        #[arg(long)]
        hidden_password: Option<String>,
        /// Live FUSE mount. Edits write through. This command stays running.
        #[arg(long, default_value_t = false)]
        live: bool,
    },
    Dismount {
        /// Mount id from `dc mount --id …` (default: "default")
        #[arg(long, default_value = "default")]
        id: String,
    },
    /// Show unlocked volume metadata
    Info {
        path: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        password_env: Option<String>,
        #[arg(long)]
        keyfile: Vec<PathBuf>,
        #[arg(long, default_value_t = 0)]
        pim: i32,
        /// VeraCrypt PKCS-5 PRF: auto, sha512, sha256, blake2s, whirlpool, streebog, argon2
        #[arg(long, default_value = "auto")]
        prf: String,
    },
    /// Change volume password (DC01; keeps master key / ciphertext)
    Chpasswd {
        path: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        password_env: Option<String>,
        #[arg(long)]
        new_password: Option<String>,
        #[arg(long)]
        keyfile: Vec<PathBuf>,
        /// Keyfiles that will apply after the change (default: same as --keyfile)
        #[arg(long)]
        new_keyfile: Vec<PathBuf>,
    },
    /// Header backup / restore (primary + hidden slots)
    Header {
        #[command(subcommand)]
        cmd: HeaderCmd,
    },
    /// List active mounts
    Status,
    /// Favorites management
    Favorite {
        #[command(subcommand)]
        cmd: FavCmd,
    },
    /// ML-KEM-768 key wrap utilities
    Keywrap {
        #[command(subcommand)]
        cmd: KeywrapCmd,
    },
    /// Time Argon2id for DC01 defaults, or a VeraCrypt PIM (`--pim`)
    Bench {
        /// VeraCrypt PIM to time (0 = default PIM 12). Omit to time DC01 defaults only.
        #[arg(long)]
        pim: Option<i32>,
    },
    /// Write a random keyfile (mode 0600). VeraCrypt-style keyfile generator.
    Keyfile {
        path: PathBuf,
        /// Length in bytes (1..=1048576)
        #[arg(long, default_value_t = 64)]
        bytes: u32,
    },
    /// Print the file-container recovery steps. Does not attach a system disk.
    Rescue {
        /// Optional header backup to check
        #[arg(long)]
        check: Option<PathBuf>,
    },
    /// Print the mount backends this build supports.
    Platforms,
    /// Validate a system-device helper request. Does not call dmsetup.
    Attach {
        /// Absolute /dev path. Not a file container.
        #[arg(long)]
        device: String,
        /// Mapper token, not a path.
        #[arg(long)]
        mapper: String,
    },
}

#[derive(Subcommand, Debug)]
enum HeaderCmd {
    /// Write primary+hidden header slots to a backup file (mode 0600)
    Backup {
        container: PathBuf,
        outfile: PathBuf,
    },
    /// Restore primary+hidden header slots from a backup file
    Restore { container: PathBuf, infile: PathBuf },
    /// Check a header backup file without writing to a container
    Check { infile: PathBuf },
}

#[derive(Subcommand, Debug)]
enum FavCmd {
    List,
    Add {
        path: PathBuf,
        #[arg(long)]
        label: String,
        #[arg(long, default_value_t = false)]
        automount: bool,
    },
    Remove {
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum KeywrapCmd {
    Gen {
        #[arg(long)]
        ek: PathBuf,
        #[arg(long)]
        dk: PathBuf,
    },
    Wrap {
        #[arg(long)]
        ek: PathBuf,
        #[arg(long)]
        infile: PathBuf,
        #[arg(long)]
        outfile: PathBuf,
    },
    Unwrap {
        #[arg(long)]
        dk: PathBuf,
        #[arg(long)]
        infile: PathBuf,
        #[arg(long)]
        outfile: PathBuf,
    },
}

/// Parse sizes like `16777216`, `16M`, `1G`, `512K` (binary units).
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size".into());
    }
    let (num, mult) = match s.as_bytes().last().map(|c| c.to_ascii_uppercase()) {
        Some(b'K') => (&s[..s.len() - 1], 1024u64),
        Some(b'M') => (&s[..s.len() - 1], 1024 * 1024),
        Some(b'G') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        Some(b'T') => (&s[..s.len() - 1], 1024u64.pow(4)),
        _ => (s, 1u64),
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid size: {s}"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("size overflow: {s}"))
}

fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0usize;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.2} {}", UNITS[i])
    }
}

fn read_password(
    opt: Option<String>,
    password_env: Option<String>,
    prompt: &str,
) -> Result<Zeroizing<String>> {
    if let Some(p) = opt {
        return Ok(Zeroizing::new(p));
    }
    if let Some(var) = password_env {
        let p = std::env::var(&var).with_context(|| format!("env {var}"))?;
        return Ok(Zeroizing::new(p));
    }
    // Silent TTY prompt when possible; fall back to stdin line (may echo on weird pipes).
    match rpassword::prompt_password(prompt) {
        Ok(p) => Ok(Zeroizing::new(p)),
        Err(_) => {
            eprint!("{prompt}");
            let _ = io::stderr().flush();
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            Ok(Zeroizing::new(
                line.trim_end_matches(['\r', '\n']).to_string(),
            ))
        }
    }
}

fn read_password_confirmed(
    opt: Option<String>,
    prompt: &str,
    confirm_prompt: &str,
) -> Result<Zeroizing<String>> {
    if let Some(p) = opt {
        return Ok(Zeroizing::new(p));
    }
    let a = read_password(None, None, prompt)?;
    let b = read_password(None, None, confirm_prompt)?;
    if a.as_str() != b.as_str() {
        bail!("passwords do not match");
    }
    Ok(a)
}

fn load_keyfiles(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for p in paths {
        out.push(fs::read(p).with_context(|| format!("read keyfile {}", p.display()))?);
    }
    Ok(out)
}

fn parse_prf(s: &str) -> Result<Option<PrfId>> {
    match s.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => Ok(None),
        "sha512" | "hmac-sha512" | "hmac-sha-512" => Ok(Some(PrfId::Sha512)),
        "sha256" | "hmac-sha256" | "hmac-sha-256" => Ok(Some(PrfId::Sha256)),
        "blake2s" | "hmac-blake2s" => Ok(Some(PrfId::Blake2s)),
        "whirlpool" | "hmac-whirlpool" => Ok(Some(PrfId::Whirlpool)),
        "streebog" | "hmac-streebog" => Ok(Some(PrfId::Streebog)),
        "argon2" | "argon2id" => Ok(Some(PrfId::Argon2id)),
        other => bail!(
            "unknown --prf {other} (auto, sha512, sha256, blake2s, whirlpool, streebog, argon2)"
        ),
    }
}

fn write_keyfile(path: &std::path::Path, bytes: u32) -> Result<()> {
    if bytes == 0 || bytes > 1024 * 1024 {
        bail!("--bytes must be 1..=1048576");
    }
    let mut buf = vec![0u8; bytes as usize];
    fill_random(&mut buf).map_err(|e| anyhow::anyhow!("rng: {e}"))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(&buf)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, &buf)?;
    }
    buf.zeroize();
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Create {
            path,
            size,
            password,
            keyfile,
            fs,
            hidden_size,
            hidden_password,
            wipe,
        } => {
            let pw = read_password_confirmed(password, "Password: ", "Confirm password: ")?;
            let kfs = load_keyfiles(&keyfile)?;
            let kf_refs: Vec<&[u8]> = kfs.iter().map(|v| v.as_slice()).collect();
            let opts = CreateOptions {
                password: pw.as_bytes(),
                keyfiles: &kf_refs,
                size,
                sector_size: 512,
                hidden_size: None,
                time_cost: DC01_DEFAULT_TIME,
                memory_kib: DC01_DEFAULT_MEM_KIB,
                parallelism: DC01_DEFAULT_PARALLELISM,
                sparse: !wipe,
            };
            let hp = if hidden_size.is_some() {
                Some(read_password_confirmed(
                    hidden_password,
                    "Hidden password: ",
                    "Confirm hidden password: ",
                )?)
            } else {
                None
            };
            if wipe {
                let mut last_pct = 0u64;
                let mut report = |done: u64, total: u64| {
                    let pct = done.saturating_mul(100).checked_div(total).unwrap_or(100);
                    if pct == 100 || pct >= last_pct + 5 {
                        last_pct = pct;
                        eprint!(
                            "\rwiping {pct:>3}%  {}/{}",
                            format_bytes(done),
                            format_bytes(total)
                        );
                        let _ = io::stderr().flush();
                    }
                };
                if let Some(hs) = hidden_size {
                    create_container_with_hidden_progress(
                        &path,
                        &opts,
                        hp.as_ref().unwrap().as_bytes(),
                        hs,
                        &mut report,
                    )?;
                } else {
                    create_container_with_progress(&path, &opts, &mut report)?;
                }
                eprintln!();
            } else if let Some(hs) = hidden_size {
                create_container_with_hidden(&path, &opts, hp.as_ref().unwrap().as_bytes(), hs)?;
            } else {
                create_container(&path, &opts)?;
            }

            let fs_ty = FsType::parse(&fs).ok_or_else(|| anyhow::anyhow!("unknown --fs {fs}"))?;
            #[cfg(target_os = "linux")]
            {
                if fs_ty != FsType::None {
                    let vol = open_container(
                        &path,
                        &OpenOptions {
                            password: pw.as_bytes(),
                            keyfiles: &kf_refs,
                            pim: 0,
                            prf: None,
                            protect_hidden: false,
                            hidden_password: None,
                        },
                    )?;
                    format_volume(Arc::new(Mutex::new(vol)), fs_ty)?;
                    if let Some(ref hidden_pw) = hp {
                        let hvol = open_container(
                            &path,
                            &OpenOptions {
                                password: hidden_pw.as_bytes(),
                                keyfiles: &kf_refs,
                                pim: 0,
                                prf: None,
                                protect_hidden: false,
                                hidden_password: None,
                            },
                        )?;
                        format_volume(Arc::new(Mutex::new(hvol)), fs_ty)?;
                    }
                    println!(
                        "created DC01 container {} (size={}, fs={fs})",
                        path.display(),
                        format_bytes(size)
                    );
                } else {
                    println!(
                        "created DC01 container {} (size={}, fs=none)",
                        path.display(),
                        format_bytes(size)
                    );
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = fs_ty;
                println!(
                    "created DC01 container {} (size={})",
                    path.display(),
                    format_bytes(size)
                );
            }
        }
        Commands::Mount {
            path,
            mountpoint,
            password,
            password_env,
            keyfile,
            pim,
            prf,
            id,
            fs,
            protect_hidden,
            hidden_password,
            live,
        } => {
            let pw = read_password(password, password_env, "Password: ")?;
            let prf = parse_prf(&prf)?;
            let hp = if protect_hidden {
                Some(read_password(hidden_password, None, "Hidden password: ")?)
            } else {
                None
            };
            let kfs = load_keyfiles(&keyfile)?;
            let kf_refs: Vec<&[u8]> = kfs.iter().map(|v| v.as_slice()).collect();
            #[cfg(target_os = "linux")]
            {
                let fs_hint = if fs == "auto" {
                    FsType::None
                } else {
                    FsType::parse(&fs).ok_or_else(|| anyhow::anyhow!("unknown --fs {fs}"))?
                };
                let open = OpenOptions {
                    password: pw.as_bytes(),
                    keyfiles: &kf_refs,
                    pim,
                    prf,
                    protect_hidden,
                    hidden_password: hp.as_ref().map(|s| s.as_bytes()),
                };
                let st = linux_mount(
                    &path,
                    &LinuxMountOptions {
                        id: &id,
                        mountpoint: &mountpoint,
                        open,
                        fs_hint,
                        live,
                    },
                )?;
                println!(
                    "mounted {} → {} (backend={}, encryption={}, hash={}, id={})",
                    path.display(),
                    mountpoint.display(),
                    st.backend,
                    if st.cipher.is_empty() {
                        "unknown"
                    } else {
                        st.cipher.as_str()
                    },
                    if st.kdf.is_empty() { "unknown" } else { st.kdf.as_str() },
                    st.id
                );
                if st.backend == "fat-fuse" {
                    println!(
                        "live mount — edits write through. Leave this running. `dc dismount --id {id}` from another terminal unmounts it."
                    );
                    loop {
                        let text = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
                        if !text.contains(&mountpoint.display().to_string()) {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                } else if st.backend == "fat-checkout" {
                    println!(
                        "note: checkout mount — edit files in the mountpoint, then `dc dismount --id {id}` to sync (no password)"
                    );
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (mountpoint, pim, prf, id, fs, protect_hidden, hp, kf_refs);
                bail!("mount is implemented for Linux first; Windows mount uses the filter driver");
            }
        }
        Commands::Dismount { id } => {
            #[cfg(target_os = "linux")]
            {
                let st =
                    load_mount_state(&id)?.ok_or_else(|| anyhow::anyhow!("not mounted: {id}"))?;
                linux_dismount(&id)?;
                println!("dismounted {id} ({})", st.mountpoint.display());
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = id;
                bail!("dismount is implemented for Linux first");
            }
        }
        Commands::Info {
            path,
            password,
            password_env,
            keyfile,
            pim,
            prf,
        } => {
            let pw = read_password(password, password_env, "Password: ")?;
            let prf = parse_prf(&prf)?;
            let kfs = load_keyfiles(&keyfile)?;
            let kf_refs: Vec<&[u8]> = kfs.iter().map(|v| v.as_slice()).collect();
            let vol = open_container(
                &path,
                &OpenOptions {
                    password: pw.as_bytes(),
                    keyfiles: &kf_refs,
                    pim,
                    prf,
                    protect_hidden: false,
                    hidden_password: None,
                },
            )?;
            println!("path:          {}", path.display());
            println!("kind:          {:?}", vol.kind);
            println!("sector_size:   {}", vol.sector_size);
            println!("data_offset:   {}", vol.data_offset);
            println!(
                "data_length:   {} ({})",
                vol.data_length,
                format_bytes(vol.data_length)
            );
            println!("hidden:        {}", vol.is_hidden);
            println!("encryption:    {}", vol.cipher.label());
            println!("hash:          {}", vol.kdf);
            dismount_session(vol);
        }
        Commands::Chpasswd {
            path,
            password,
            password_env,
            new_password,
            keyfile,
            new_keyfile,
        } => {
            let old = read_password(password, password_env, "Current password: ")?;
            let new =
                read_password_confirmed(new_password, "New password: ", "Confirm new password: ")?;
            let kfs = load_keyfiles(&keyfile)?;
            let kf_refs: Vec<&[u8]> = kfs.iter().map(|v| v.as_slice()).collect();
            let new_kfs = if new_keyfile.is_empty() {
                kfs.clone()
            } else {
                load_keyfiles(&new_keyfile)?
            };
            let new_kf_refs: Vec<&[u8]> = new_kfs.iter().map(|v| v.as_slice()).collect();
            change_password(
                &path,
                &OpenOptions {
                    password: old.as_bytes(),
                    keyfiles: &kf_refs,
                    pim: 0,
                    prf: None,
                    protect_hidden: false,
                    hidden_password: None,
                },
                new.as_bytes(),
                &new_kf_refs,
            )?;
            println!("password updated for {}", path.display());
            println!("tip: old password no longer unlocks this volume");
        }
        Commands::Header { cmd } => match cmd {
            HeaderCmd::Backup { container, outfile } => {
                backup_headers(&container, &outfile)?;
                println!(
                    "wrote header backup {} (primary+hidden slots)",
                    outfile.display()
                );
            }
            HeaderCmd::Restore { container, infile } => {
                restore_headers(&container, &infile)?;
                println!(
                    "restored headers into {} from {}",
                    container.display(),
                    infile.display()
                );
            }
            HeaderCmd::Check { infile } => {
                let n = inspect_header_backup(&infile)?;
                println!("header backup ok {} ({} bytes of header slots)", infile.display(), n);
            }
        },
        Commands::Status => {
            #[cfg(target_os = "linux")]
            {
                use dc_volume::list_mount_states;
                let mounts = list_mount_states()?;
                if mounts.is_empty() {
                    println!("(no mounts)");
                } else {
                    println!(
                        "{:<12} {:<14} {:<8} CONTAINER → MOUNTPOINT",
                        "ID", "BACKEND", "FS"
                    );
                    for st in mounts {
                        println!(
                            "{:<12} {:<14} {:<8} {} → {}",
                            st.id,
                            st.backend,
                            st.fs,
                            st.container.display(),
                            st.mountpoint.display()
                        );
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                println!("(status available on Linux)");
            }
        }
        Commands::Favorite { cmd } => match cmd {
            FavCmd::List => {
                for f in list_favorites()? {
                    println!(
                        "{}\t{}\tautomount={}",
                        f.label,
                        f.path.display(),
                        f.automount
                    );
                }
            }
            FavCmd::Add {
                path,
                label,
                automount,
            } => {
                add_favorite(Favorite {
                    path,
                    label,
                    automount,
                })?;
                println!("favorite added");
            }
            FavCmd::Remove { path } => {
                remove_favorite(&path)?;
                println!("favorite removed");
            }
        },
        Commands::Keywrap { cmd } => match cmd {
            KeywrapCmd::Gen { ek, dk } => {
                let (ek_bytes, dk_bytes) = mlkem_generate_keypair()?;
                fs::write(ek, ek_bytes)?;
                fs::write(dk, dk_bytes)?;
                println!("wrote ML-KEM-768 keypair");
            }
            KeywrapCmd::Wrap {
                ek,
                infile,
                outfile,
            } => {
                let ek_bytes = fs::read(ek)?;
                let mut pt = fs::read(infile)?;
                while pt.len() % 16 != 0 {
                    pt.push(0);
                }
                let wrapped = mlkem_encapsulate_key(&ek_bytes, &pt)?;
                let mut out = Vec::new();
                out.extend_from_slice(&(wrapped.encapsulated_key.len() as u32).to_le_bytes());
                out.extend_from_slice(&wrapped.encapsulated_key);
                out.extend_from_slice(&wrapped.ciphertext);
                fs::write(outfile, out)?;
            }
            KeywrapCmd::Unwrap {
                dk,
                infile,
                outfile,
            } => {
                let dk_bytes = fs::read(dk)?;
                let data = fs::read(infile)?;
                if data.len() < 4 {
                    bail!("truncated wrap file");
                }
                let n = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
                if data.len() < 4 + n {
                    bail!("truncated wrap file");
                }
                let wrapped = WrappedKey {
                    encapsulated_key: data[4..4 + n].to_vec(),
                    ciphertext: data[4 + n..].to_vec(),
                };
                let pt = mlkem_decapsulate_key(&dk_bytes, &wrapped)?;
                fs::write(outfile, pt.as_slice())?;
            }
        },
        Commands::Bench { pim } => {
            let dc = bench_argon2id(
                "dc01",
                DC01_DEFAULT_TIME,
                DC01_DEFAULT_MEM_KIB,
                DC01_DEFAULT_PARALLELISM,
            )?;
            println!(
                "DC01 Argon2id  t={} m={} KiB p={}  {} ms",
                dc.time_cost, dc.memory_kib, dc.parallelism, dc.elapsed_ms
            );
            if let Some(pim) = pim {
                let b = bench_veracrypt_pim(pim)?;
                println!(
                    "VeraCrypt Argon2id PIM {pim}  t={} m={} KiB p={}  {} ms",
                    b.time_cost, b.memory_kib, b.parallelism, b.elapsed_ms
                );
                if pim == 0 {
                    println!("(PIM 0 uses VeraCrypt default PIM 12)");
                }
            } else {
                println!(
                    "pass --pim N to time a VeraCrypt Argon2id PIM (0 = default PIM 12; can be slow)"
                );
            }
        }
        Commands::Keyfile { path, bytes } => {
            write_keyfile(&path, bytes)?;
            println!("wrote keyfile {} ({} bytes)", path.display(), bytes);
        }
        Commands::Rescue { check } => {
            println!("File-container recovery. This does not attach a system disk.");
            println!("1. Boot a Linux live image with this dc binary.");
            println!("2. dc info VOLUME   — confirm the password still opens the header.");
            println!("3. dc header restore VOLUME BACKUP   — only if you have a DCHDR01 backup.");
            println!("4. dc mount VOLUME MOUNTPOINT   — checkout mount. Use --live only if this process can stay open.");
            println!("System encryption and /dev/mapper attach are not in this build.");
            if let Some(path) = check {
                let n = inspect_header_backup(&path)?;
                println!("header backup ok {} ({} bytes of header slots)", path.display(), n);
            }
        }
        Commands::Platforms => {
            for line in dc_platform::platform_report() {
                println!("{line}");
            }
        }
        Commands::Attach { device, mapper } => {
            dc_platform::validate_helper_request(&device, &mapper)?;
            bail!(
                "refused: this build does not call dmsetup or cryptsetup. File containers use dc mount."
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_size;

    #[test]
    fn parse_human_sizes() {
        assert_eq!(parse_size("16").unwrap(), 16);
        assert_eq!(parse_size("16M").unwrap(), 16 * 1024 * 1024);
        assert_eq!(parse_size("1g").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("512K").unwrap(), 512 * 1024);
    }
}
