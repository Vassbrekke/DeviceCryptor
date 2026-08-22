use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use dc_crypto::{mlkem_decapsulate_key, mlkem_encapsulate_key, mlkem_generate_keypair, WrappedKey};
use dc_format::dc01::{DC01_DEFAULT_MEM_KIB, DC01_DEFAULT_PARALLELISM, DC01_DEFAULT_TIME};
use dc_volume::{
    add_favorite, backup_headers, change_password, create_container, create_container_with_hidden,
    dismount_session, list_favorites, open_container, remove_favorite, restore_headers,
    CreateOptions, Favorite, FsType, OpenOptions,
};
use zeroize::Zeroizing;

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
        #[arg(long, default_value = "default")]
        id: String,
        #[arg(long, default_value = "auto")]
        fs: String,
        /// Protect hidden volume from outer-volume writes
        #[arg(long, default_value_t = false)]
        protect_hidden: bool,
        #[arg(long)]
        hidden_password: Option<String>,
    },
    /// Dismount and sync changes back into the container (no password — session from mount)
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
            if let Some(hs) = hidden_size {
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
            id,
            fs,
            protect_hidden,
            hidden_password,
        } => {
            let pw = read_password(password, password_env, "Password: ")?;
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
                    },
                )?;
                println!(
                    "mounted {} → {} (backend={}, id={})",
                    path.display(),
                    mountpoint.display(),
                    st.backend,
                    st.id
                );
                if st.backend == "fat-checkout" {
                    println!(
                        "note: checkout mount — edit files in the mountpoint, then `dc dismount --id {id}` to sync (no password)"
                    );
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (mountpoint, pim, id, fs, protect_hidden, hp, kf_refs);
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
        } => {
            let pw = read_password(password, password_env, "Password: ")?;
            let kfs = load_keyfiles(&keyfile)?;
            let kf_refs: Vec<&[u8]> = kfs.iter().map(|v| v.as_slice()).collect();
            let vol = open_container(
                &path,
                &OpenOptions {
                    password: pw.as_bytes(),
                    keyfiles: &kf_refs,
                    pim,
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
