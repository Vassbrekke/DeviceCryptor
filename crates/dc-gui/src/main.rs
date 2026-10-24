//! DeviceCryptor main window — classic VeraCrypt layout, not a tabbed shell.
//!
//! Volumes, Tools, and every form open in their own window. The main window
//! stays the slot list. Disk encryption remains AES-256-XTS. ML-KEM key wrap
//! and the Argon2id benchmark live under Tools.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use dc_crypto::{
    bench_argon2id, bench_veracrypt_pim, fill_random, mlkem_decapsulate_key, mlkem_encapsulate_key,
    mlkem_generate_keypair, PrfId, WrappedKey,
};
use dc_format::dc01::{DC01_DEFAULT_MEM_KIB, DC01_DEFAULT_PARALLELISM, DC01_DEFAULT_TIME};
use dc_volume::{
    add_favorite, backup_headers, change_password, create_container, create_container_with_hidden,
    dismount_session, list_favorites, open_container, remove_favorite, restore_headers,
    CreateOptions, Favorite, FsType, OpenOptions,
};
use iced::theme::Palette;
use iced::widget::{button, checkbox, column, pick_list, row, scrollable, text, text_input, Space};
use iced::{window, Color, Element, Length, Size, Subscription, Task, Theme};
use zeroize::Zeroize;

#[cfg(target_os = "linux")]
use dc_volume::{
    format_volume, linux_dismount, linux_mount, list_mount_states, LinuxMountOptions, MountState,
};

const SLOT_COUNT: u8 = 8;

fn main() -> iced::Result {
    iced::daemon(App::title, App::update, App::view)
        .theme(App::theme)
        .subscription(App::subscription)
        .run_with(App::boot)
}

fn classic_theme() -> Theme {
    Theme::custom(
        "Classic".into(),
        Palette {
            background: Color::from_rgb8(0xF0, 0xF0, 0xF0),
            text: Color::from_rgb8(0x1A, 0x1A, 0x1A),
            primary: Color::from_rgb8(0x31, 0x6A, 0xC5),
            success: Color::from_rgb8(0x2E, 0x7D, 0x32),
            danger: Color::from_rgb8(0xA1, 0x26, 0x22),
        },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Dialog {
    #[default]
    None,
    Mount,
    Create,
    Chpasswd,
    HeaderBackup,
    HeaderRestore,
    Properties,
    Favorites,
    Keywrap,
    Keyfile,
    Benchmark,
    About,
    /// Static explanation. Holds no secrets.
    Notice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Menu {
    Volumes,
    Tools,
}

/// Which window a [`window::Id`] is drawing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    Main,
    Menu(Menu),
    Dialog(Dialog),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FsChoice {
    Fat32,
    Ext4,
    None,
    Auto,
}

impl FsChoice {
    const CREATE: [FsChoice; 3] = [FsChoice::Fat32, FsChoice::Ext4, FsChoice::None];
    const MOUNT: [FsChoice; 4] = [
        FsChoice::Auto,
        FsChoice::Fat32,
        FsChoice::Ext4,
        FsChoice::None,
    ];

    fn label(self) -> &'static str {
        match self {
            FsChoice::Fat32 => "FAT",
            FsChoice::Ext4 => "ext4",
            FsChoice::None => "None",
            FsChoice::Auto => "Auto",
        }
    }

    fn as_fs_type(self) -> FsType {
        match self {
            FsChoice::Fat32 => FsType::Fat32,
            FsChoice::Ext4 => FsType::Ext4,
            FsChoice::None | FsChoice::Auto => FsType::None,
        }
    }
}

impl std::fmt::Display for FsChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// VeraCrypt PKCS-5 PRF, as on the password dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum PrfChoice {
    #[default]
    Auto,
    Sha512,
    Sha256,
    Blake2s,
    Whirlpool,
    Streebog,
    Argon2,
}

impl PrfChoice {
    const ALL: [PrfChoice; 7] = [
        PrfChoice::Auto,
        PrfChoice::Sha512,
        PrfChoice::Sha256,
        PrfChoice::Blake2s,
        PrfChoice::Whirlpool,
        PrfChoice::Streebog,
        PrfChoice::Argon2,
    ];

    fn label(self) -> &'static str {
        match self {
            PrfChoice::Auto => "Autodetect",
            PrfChoice::Sha512 => "HMAC-SHA-512",
            PrfChoice::Sha256 => "HMAC-SHA-256",
            PrfChoice::Blake2s => "HMAC-BLAKE2s",
            PrfChoice::Whirlpool => "HMAC-Whirlpool",
            PrfChoice::Streebog => "HMAC-Streebog",
            PrfChoice::Argon2 => "Argon2id",
        }
    }

    fn as_prf(self) -> Option<PrfId> {
        match self {
            PrfChoice::Auto => None,
            PrfChoice::Sha512 => Some(PrfId::Sha512),
            PrfChoice::Sha256 => Some(PrfId::Sha256),
            PrfChoice::Blake2s => Some(PrfId::Blake2s),
            PrfChoice::Whirlpool => Some(PrfId::Whirlpool),
            PrfChoice::Streebog => Some(PrfId::Streebog),
            PrfChoice::Argon2 => Some(PrfId::Argon2id),
        }
    }
}

impl std::fmt::Display for PrfChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

struct App {
    main_id: window::Id,
    surfaces: HashMap<window::Id, Surface>,
    /// Text for [`Dialog::Notice`]. Never a password.
    notice: String,
    busy: bool,
    status: String,
    volume_path: String,
    never_save_history: bool,
    selected_slot: u8,
    status_mounts: Vec<StatusRow>,

    mount_point: String,
    mount_password: String,
    mount_keyfile: String,
    mount_pim: String,
    vc_prf: PrfChoice,
    mount_fs: FsChoice,
    mount_protect_hidden: bool,
    mount_live: bool,
    mount_hidden_password: String,

    create_password: String,
    create_confirm: String,
    create_size_mb: String,
    create_fs: FsChoice,
    create_keyfile: String,
    create_hidden_mb: String,
    create_hidden_password: String,
    create_wipe: bool,

    cp_old: String,
    cp_new: String,
    cp_confirm: String,
    cp_keyfile: String,
    cp_new_keyfile: String,

    hdr_file: String,

    info_password: String,
    info_keyfile: String,
    info_pim: String,

    fav_path: String,
    fav_label: String,
    fav_automount: bool,
    fav_list: String,

    kw_ek: String,
    kw_dk: String,
    kw_infile: String,
    kw_outfile: String,

    kf_path: String,
    kf_bytes: String,
    bench_pim: String,
}

#[derive(Debug, Clone)]
struct StatusRow {
    id: String,
    backend: String,
    container: String,
    mountpoint: String,
    fs: String,
    session_store: String,
}

impl Default for App {
    fn default() -> Self {
        Self {
            main_id: window::Id::unique(),
            surfaces: HashMap::new(),
            notice: String::new(),
            busy: false,
            status: String::new(),
            volume_path: String::new(),
            never_save_history: false,
            selected_slot: 1,
            status_mounts: Vec::new(),
            mount_point: String::new(),
            mount_password: String::new(),
            mount_keyfile: String::new(),
            mount_pim: "0".into(),
            vc_prf: PrfChoice::Auto,
            mount_fs: FsChoice::Auto,
            mount_protect_hidden: false,
            mount_live: false,
            mount_hidden_password: String::new(),
            create_password: String::new(),
            create_confirm: String::new(),
            create_size_mb: "16".into(),
            create_fs: FsChoice::Fat32,
            create_keyfile: String::new(),
            create_hidden_mb: String::new(),
            create_hidden_password: String::new(),
            create_wipe: false,
            cp_old: String::new(),
            cp_new: String::new(),
            cp_confirm: String::new(),
            cp_keyfile: String::new(),
            cp_new_keyfile: String::new(),
            hdr_file: String::new(),
            info_password: String::new(),
            info_keyfile: String::new(),
            info_pim: "0".into(),
            fav_path: String::new(),
            fav_label: String::new(),
            fav_automount: false,
            fav_list: String::new(),
            kw_ek: String::new(),
            kw_dk: String::new(),
            kw_infile: String::new(),
            kw_outfile: String::new(),
            kf_path: String::new(),
            kf_bytes: "64".into(),
            bench_pim: "0".into(),
        }
    }
}

#[derive(Debug, Clone)]
enum Message {
    ToggleMenu(Menu),
    Open(Dialog),
    CloseDialog,
    CloseMenu,
    WindowClosed(window::Id),
    SelectSlot(u8),
    VolumePath(String),
    NeverSaveHistory(bool),
    SelectFile,
    SelectDevice,
    AutoMountDevices,
    DoDismountSelected,
    DoDismountAll,
    DoStatus,
    OpFinished(Result<String, String>),
    StatusLoaded(Result<Vec<StatusRow>, String>),

    MountPoint(String),
    MountPassword(String),
    MountKeyfile(String),
    MountPim(String),
    VcPrf(PrfChoice),
    MountFs(FsChoice),
    MountProtectHidden(bool),
    MountLive(bool),
    MountHiddenPassword(String),
    BrowseMountPoint,
    BrowseMountKeyfile,
    DoMount,

    CreatePassword(String),
    CreateConfirm(String),
    CreateSize(String),
    CreateFs(FsChoice),
    CreateKeyfile(String),
    CreateHiddenMb(String),
    CreateHiddenPassword(String),
    CreateWipe(bool),
    BrowseCreateKeyfile,
    DoCreate,

    CpOld(String),
    CpNew(String),
    CpConfirm(String),
    CpKeyfile(String),
    CpNewKeyfile(String),
    BrowseCpKeyfile,
    BrowseCpNewKeyfile,
    DoChpasswd,

    HdrFile(String),
    BrowseHdrSave,
    BrowseHdrOpen,
    DoHeaderBackup,
    DoHeaderRestore,

    InfoPassword(String),
    InfoKeyfile(String),
    InfoPim(String),
    BrowseInfoKeyfile,
    DoInfo,

    FavPath(String),
    FavLabel(String),
    FavAutomount(bool),
    BrowseFavPath,
    DoFavList,
    DoFavAdd,
    DoFavRemove,
    UseFavorite(String),

    KwEk(String),
    KwDk(String),
    KwInfile(String),
    KwOutfile(String),
    BrowseKwEk,
    BrowseKwDk,
    BrowseKwIn,
    BrowseKwOut,
    DoKwGen,
    DoKwWrap,
    DoKwUnwrap,

    KfPath(String),
    KfBytes(String),
    BrowseKfPath,
    DoKeyfile,

    BenchPim(String),
    DoBenchDc01,
    DoBenchPim,
}

impl App {
    fn boot() -> (Self, Task<Message>) {
        let (main_id, open) = window::open(window::Settings {
            size: Size::new(920.0, 540.0),
            min_size: Some(Size::new(760.0, 460.0)),
            position: window::Position::Centered,
            ..window::Settings::default()
        });
        let mut app = Self::default();
        app.main_id = main_id;
        app.surfaces.insert(main_id, Surface::Main);
        let refresh = app.refresh_status();
        (app, Task::batch([open.discard(), refresh]))
    }

    fn title(&self, id: window::Id) -> String {
        match self.surfaces.get(&id).copied() {
            Some(Surface::Menu(Menu::Volumes)) => "Volumes".into(),
            Some(Surface::Menu(Menu::Tools)) => "Tools".into(),
            Some(Surface::Dialog(dialog)) => dialog_title(dialog).into(),
            _ => "DeviceCryptor".into(),
        }
    }

    fn theme(&self, _id: window::Id) -> Theme {
        classic_theme()
    }

    fn subscription(&self) -> Subscription<Message> {
        window::close_events().map(Message::WindowClosed)
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ToggleMenu(menu) => {
                if self.menu_kind() == Some(menu) {
                    return self.close_where(|surface| matches!(surface, Surface::Menu(_)));
                }
                return self.open_menu(menu);
            }
            Message::Open(dialog) => {
                let menus = self.close_where(|surface| matches!(surface, Surface::Menu(_)));
                let same = self.current_dialog() == dialog;
                if !same && dialog == Dialog::Mount && self.mount_point.trim().is_empty() {
                    self.mount_point = default_mountpoint(self.selected_slot);
                }
                let opened = self.open_dialog(dialog);
                if !same && dialog == Dialog::Favorites {
                    return Task::batch([menus, opened, self.run_op(fav_list)]);
                }
                return Task::batch([menus, opened]);
            }
            Message::CloseDialog => {
                return self.close_where(|surface| matches!(surface, Surface::Dialog(_)));
            }
            Message::CloseMenu => {
                return self.close_where(|surface| matches!(surface, Surface::Menu(_)));
            }
            Message::WindowClosed(id) => {
                if id == self.main_id {
                    self.clear_secrets();
                    return iced::exit();
                }
                if matches!(self.surfaces.remove(&id), Some(Surface::Dialog(_))) {
                    self.clear_secrets();
                }
            }
            Message::SelectSlot(n) => {
                self.selected_slot = n;
                if let Some(row) = self.mount_for_slot(n) {
                    self.volume_path = row.container.clone();
                }
            }
            Message::VolumePath(v) => self.volume_path = v,
            Message::NeverSaveHistory(v) => self.never_save_history = v,
            Message::SelectFile => {
                if let Some(p) = rfd::FileDialog::new().set_title("Select File").pick_file() {
                    self.volume_path = p.display().to_string();
                }
            }
            Message::SelectDevice => {
                self.notice = "Select Device is not available in this build. System and partition encryption are not ready. Use Select File for a container.".into();
                return self.open_dialog(Dialog::Notice);
            }
            Message::AutoMountDevices => {
                self.notice = "Auto-Mount Devices is not available in this build. File containers only. Open Tools, then Favorite Volumes, then Mount.".into();
                return self.open_dialog(Dialog::Notice);
            }
            Message::DoDismountSelected => {
                let id = slot_id(self.selected_slot);
                let op = self.run_op(move || run_dismount(&id));
                return Task::batch([
                    self.close_where(|surface| matches!(surface, Surface::Menu(_))),
                    op,
                ]);
            }
            Message::DoDismountAll => {
                let op = self.run_op(run_dismount_all);
                return Task::batch([
                    self.close_where(|surface| matches!(surface, Surface::Menu(_))),
                    op,
                ]);
            }
            Message::DoStatus => {
                self.status = "working…".into();
                return self.refresh_status();
            }
            Message::OpFinished(res) => {
                self.busy = false;
                match res {
                    Ok(s) => {
                        let dialog = self.current_dialog();
                        let stay = matches!(
                            dialog,
                            Dialog::Favorites
                                | Dialog::Keywrap
                                | Dialog::Keyfile
                                | Dialog::Benchmark
                                | Dialog::Properties
                                | Dialog::About
                                | Dialog::Notice
                                | Dialog::None
                        );
                        if dialog == Dialog::Favorites {
                            self.fav_list = s;
                            self.status = "favorites updated".into();
                        } else {
                            self.status = s;
                        }
                        self.clear_secrets();
                        let refresh = self.refresh_status_quiet();
                        if stay {
                            return refresh;
                        }
                        if self.never_save_history {
                            self.volume_path.clear();
                        }
                        return Task::batch([
                            self.close_where(|surface| matches!(surface, Surface::Dialog(_))),
                            refresh,
                        ]);
                    }
                    Err(e) => self.status = format!("error: {e}"),
                }
            }
            Message::StatusLoaded(res) => {
                self.busy = false;
                match res {
                    Ok(rows) => {
                        self.status_mounts = rows;
                        if self.status.is_empty() || self.status == "working…" {
                            self.status = if self.status_mounts.is_empty() {
                                "No volumes mounted".into()
                            } else {
                                format!("{} volume(s) mounted", self.status_mounts.len())
                            };
                        }
                    }
                    Err(e) => {
                        if self.status.is_empty() || self.status == "working…" {
                            self.status = format!("error: {e}");
                        }
                    }
                }
            }

            Message::MountPoint(v) => self.mount_point = v,
            Message::MountPassword(v) => self.mount_password = v,
            Message::MountKeyfile(v) => self.mount_keyfile = v,
            Message::MountPim(v) => self.mount_pim = v,
            Message::VcPrf(v) => self.vc_prf = v,
            Message::MountFs(v) => self.mount_fs = v,
            Message::MountProtectHidden(v) => self.mount_protect_hidden = v,
            Message::MountLive(v) => self.mount_live = v,
            Message::MountHiddenPassword(v) => self.mount_hidden_password = v,
            Message::BrowseMountPoint => {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("Mount directory")
                    .pick_folder()
                {
                    self.mount_point = p.display().to_string();
                }
            }
            Message::BrowseMountKeyfile => {
                if let Some(p) = rfd::FileDialog::new().set_title("Keyfile").pick_file() {
                    self.mount_keyfile = p.display().to_string();
                }
            }
            Message::DoMount => {
                let snap = MountSnap::from(&*self);
                return self.run_op(move || snap.run());
            }

            Message::CreatePassword(v) => self.create_password = v,
            Message::CreateConfirm(v) => self.create_confirm = v,
            Message::CreateSize(v) => self.create_size_mb = v,
            Message::CreateFs(v) => self.create_fs = v,
            Message::CreateKeyfile(v) => self.create_keyfile = v,
            Message::CreateHiddenMb(v) => self.create_hidden_mb = v,
            Message::CreateHiddenPassword(v) => self.create_hidden_password = v,
            Message::CreateWipe(v) => self.create_wipe = v,
            Message::BrowseCreateKeyfile => {
                if let Some(p) = rfd::FileDialog::new().set_title("Keyfile").pick_file() {
                    self.create_keyfile = p.display().to_string();
                }
            }
            Message::DoCreate => {
                let snap = CreateSnap::from(&*self);
                return self.run_op(move || snap.run());
            }

            Message::CpOld(v) => self.cp_old = v,
            Message::CpNew(v) => self.cp_new = v,
            Message::CpConfirm(v) => self.cp_confirm = v,
            Message::CpKeyfile(v) => self.cp_keyfile = v,
            Message::CpNewKeyfile(v) => self.cp_new_keyfile = v,
            Message::BrowseCpKeyfile => {
                if let Some(p) = rfd::FileDialog::new().set_title("Keyfile").pick_file() {
                    self.cp_keyfile = p.display().to_string();
                }
            }
            Message::BrowseCpNewKeyfile => {
                if let Some(p) = rfd::FileDialog::new().set_title("New keyfile").pick_file() {
                    self.cp_new_keyfile = p.display().to_string();
                }
            }
            Message::DoChpasswd => {
                let snap = ChpasswdSnap::from(&*self);
                return self.run_op(move || snap.run());
            }

            Message::HdrFile(v) => self.hdr_file = v,
            Message::BrowseHdrSave => {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("Backup Volume Header")
                    .save_file()
                {
                    self.hdr_file = p.display().to_string();
                }
            }
            Message::BrowseHdrOpen => {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("Restore Volume Header")
                    .pick_file()
                {
                    self.hdr_file = p.display().to_string();
                }
            }
            Message::DoHeaderBackup => {
                let container = PathBuf::from(&self.volume_path);
                let file = PathBuf::from(&self.hdr_file);
                return self.run_op(move || {
                    if container.as_os_str().is_empty() || file.as_os_str().is_empty() {
                        anyhow::bail!("volume and backup file required");
                    }
                    backup_headers(&container, &file)?;
                    Ok(format!(
                        "header backup written to {} (mode 0600)",
                        file.display()
                    ))
                });
            }
            Message::DoHeaderRestore => {
                let container = PathBuf::from(&self.volume_path);
                let file = PathBuf::from(&self.hdr_file);
                return self.run_op(move || {
                    if container.as_os_str().is_empty() || file.as_os_str().is_empty() {
                        anyhow::bail!("volume and backup file required");
                    }
                    restore_headers(&container, &file)?;
                    Ok(format!("header restored into {}", container.display()))
                });
            }

            Message::InfoPassword(v) => self.info_password = v,
            Message::InfoKeyfile(v) => self.info_keyfile = v,
            Message::InfoPim(v) => self.info_pim = v,
            Message::BrowseInfoKeyfile => {
                if let Some(p) = rfd::FileDialog::new().set_title("Keyfile").pick_file() {
                    self.info_keyfile = p.display().to_string();
                }
            }
            Message::DoInfo => {
                let snap = InfoSnap::from(&*self);
                return self.run_op(move || snap.run());
            }

            Message::FavPath(v) => self.fav_path = v,
            Message::FavLabel(v) => self.fav_label = v,
            Message::FavAutomount(v) => self.fav_automount = v,
            Message::BrowseFavPath => {
                if let Some(p) = rfd::FileDialog::new().set_title("Container").pick_file() {
                    self.fav_path = p.display().to_string();
                }
            }
            Message::DoFavList => return self.run_op(fav_list),
            Message::DoFavAdd => {
                let path = PathBuf::from(self.fav_path.clone());
                let label = self.fav_label.clone();
                let automount = self.fav_automount;
                return self.run_op(move || {
                    if label.trim().is_empty() || path.as_os_str().is_empty() {
                        anyhow::bail!("label and path required");
                    }
                    add_favorite(Favorite {
                        path,
                        label,
                        automount,
                    })?;
                    fav_list()
                });
            }
            Message::DoFavRemove => {
                let path = PathBuf::from(self.fav_path.clone());
                return self.run_op(move || {
                    remove_favorite(&path)?;
                    fav_list()
                });
            }
            Message::UseFavorite(path) => {
                self.volume_path = path;
                self.status = "volume selected — enter the password with Mount".into();
                return self.close_where(|surface| matches!(surface, Surface::Dialog(_)));
            }

            Message::KwEk(v) => self.kw_ek = v,
            Message::KwDk(v) => self.kw_dk = v,
            Message::KwInfile(v) => self.kw_infile = v,
            Message::KwOutfile(v) => self.kw_outfile = v,
            Message::BrowseKwEk => {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("Encapsulation key")
                    .save_file()
                {
                    self.kw_ek = p.display().to_string();
                }
            }
            Message::BrowseKwDk => {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("Decapsulation key")
                    .save_file()
                {
                    self.kw_dk = p.display().to_string();
                }
            }
            Message::BrowseKwIn => {
                if let Some(p) = rfd::FileDialog::new().set_title("Input").pick_file() {
                    self.kw_infile = p.display().to_string();
                }
            }
            Message::BrowseKwOut => {
                if let Some(p) = rfd::FileDialog::new().set_title("Output").save_file() {
                    self.kw_outfile = p.display().to_string();
                }
            }
            Message::DoKwGen => {
                let ek = PathBuf::from(self.kw_ek.clone());
                let dk = PathBuf::from(self.kw_dk.clone());
                return self.run_op(move || {
                    let (ekb, dkb) = mlkem_generate_keypair()?;
                    fs::write(&ek, ekb)?;
                    fs::write(&dk, dkb)?;
                    Ok(format!(
                        "wrote ML-KEM-768 keypair\n  ek: {}\n  dk: {}",
                        ek.display(),
                        dk.display()
                    ))
                });
            }
            Message::DoKwWrap => {
                let ek = PathBuf::from(self.kw_ek.clone());
                let infile = PathBuf::from(self.kw_infile.clone());
                let outfile = PathBuf::from(self.kw_outfile.clone());
                return self.run_op(move || {
                    let ek_bytes = fs::read(&ek)?;
                    let mut pt = fs::read(&infile)?;
                    while pt.len() % 16 != 0 {
                        pt.push(0);
                    }
                    let wrapped = mlkem_encapsulate_key(&ek_bytes, &pt)?;
                    let mut out = Vec::new();
                    out.extend_from_slice(&(wrapped.encapsulated_key.len() as u32).to_le_bytes());
                    out.extend_from_slice(&wrapped.encapsulated_key);
                    out.extend_from_slice(&wrapped.ciphertext);
                    fs::write(&outfile, out)?;
                    Ok(format!("wrapped → {}", outfile.display()))
                });
            }
            Message::DoKwUnwrap => {
                let dk = PathBuf::from(self.kw_dk.clone());
                let infile = PathBuf::from(self.kw_infile.clone());
                let outfile = PathBuf::from(self.kw_outfile.clone());
                return self.run_op(move || {
                    let dk_bytes = fs::read(&dk)?;
                    let data = fs::read(&infile)?;
                    if data.len() < 4 {
                        anyhow::bail!("truncated wrap file");
                    }
                    let n = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
                    if data.len() < 4 + n {
                        anyhow::bail!("truncated wrap file");
                    }
                    let wrapped = WrappedKey {
                        encapsulated_key: data[4..4 + n].to_vec(),
                        ciphertext: data[4 + n..].to_vec(),
                    };
                    let pt = mlkem_decapsulate_key(&dk_bytes, &wrapped)?;
                    fs::write(&outfile, pt.as_slice())?;
                    Ok(format!("unwrapped → {}", outfile.display()))
                });
            }

            Message::KfPath(v) => self.kf_path = v,
            Message::KfBytes(v) => self.kf_bytes = v,
            Message::BrowseKfPath => {
                if let Some(p) = rfd::FileDialog::new().set_title("Keyfile").save_file() {
                    self.kf_path = p.display().to_string();
                }
            }
            Message::DoKeyfile => {
                let path = PathBuf::from(self.kf_path.clone());
                let bytes = self.kf_bytes.clone();
                return self.run_op(move || write_keyfile(&path, &bytes));
            }

            Message::BenchPim(v) => self.bench_pim = v,
            Message::DoBenchDc01 => {
                return self.run_op(|| {
                    let b = bench_argon2id(
                        "dc01",
                        DC01_DEFAULT_TIME,
                        DC01_DEFAULT_MEM_KIB,
                        DC01_DEFAULT_PARALLELISM,
                    )?;
                    Ok(format!(
                        "DC01 Argon2id  t={} m={} KiB p={}  {} ms",
                        b.time_cost, b.memory_kib, b.parallelism, b.elapsed_ms
                    ))
                });
            }
            Message::DoBenchPim => {
                let pim = self.bench_pim.clone();
                return self.run_op(move || {
                    let pim = parse_pim(&pim)?;
                    let b = bench_veracrypt_pim(pim)?;
                    Ok(format!(
                        "VeraCrypt Argon2id PIM {pim}  t={} m={} KiB p={}  {} ms{}",
                        b.time_cost,
                        b.memory_kib,
                        b.parallelism,
                        b.elapsed_ms,
                        if pim == 0 {
                            "\n(PIM 0 uses VeraCrypt default PIM 12)"
                        } else {
                            ""
                        }
                    ))
                });
            }
        }
        Task::none()
    }

    fn clear_secrets(&mut self) {
        self.mount_password.zeroize();
        self.mount_hidden_password.zeroize();
        self.create_password.zeroize();
        self.create_confirm.zeroize();
        self.create_hidden_password.zeroize();
        self.cp_old.zeroize();
        self.cp_new.zeroize();
        self.cp_confirm.zeroize();
        self.info_password.zeroize();
    }

    fn current_dialog(&self) -> Dialog {
        self.surfaces
            .values()
            .find_map(|surface| match surface {
                Surface::Dialog(dialog) => Some(*dialog),
                _ => None,
            })
            .unwrap_or(Dialog::None)
    }

    fn menu_kind(&self) -> Option<Menu> {
        self.surfaces.values().find_map(|surface| match surface {
            Surface::Menu(menu) => Some(*menu),
            _ => None,
        })
    }

    /// Closes matching windows. Password fields are wiped when a dialog closes.
    fn close_where(&mut self, pred: impl Fn(&Surface) -> bool) -> Task<Message> {
        let ids: Vec<window::Id> = self
            .surfaces
            .iter()
            .filter_map(|(id, surface)| pred(surface).then_some(*id))
            .collect();
        let mut wipe = false;
        for id in &ids {
            if matches!(self.surfaces.remove(id), Some(Surface::Dialog(_))) {
                wipe = true;
            }
        }
        if wipe {
            self.clear_secrets();
        }
        Task::batch(ids.into_iter().map(window::close))
    }

    fn open_dialog(&mut self, dialog: Dialog) -> Task<Message> {
        if self.current_dialog() == dialog {
            if let Some(id) = self
                .surfaces
                .iter()
                .find_map(|(id, surface)| matches!(surface, Surface::Dialog(_)).then_some(*id))
            {
                return window::gain_focus(id);
            }
        }
        let close = self.close_where(|surface| matches!(surface, Surface::Dialog(_)));
        let (id, open) = window::open(dialog_window_settings(dialog));
        self.surfaces.insert(id, Surface::Dialog(dialog));
        Task::batch([close, open.discard()])
    }

    fn open_menu(&mut self, menu: Menu) -> Task<Message> {
        let close = self.close_where(|surface| matches!(surface, Surface::Menu(_)));
        let (id, open) = window::open(menu_window_settings(menu));
        self.surfaces.insert(id, Surface::Menu(menu));
        Task::batch([close, open.discard()])
    }

    fn mount_for_slot(&self, n: u8) -> Option<&StatusRow> {
        let id = slot_id(n);
        self.status_mounts.iter().find(|m| m.id == id)
    }

    fn run_op<F>(&mut self, f: F) -> Task<Message>
    where
        F: FnOnce() -> anyhow::Result<String> + Send + 'static,
    {
        if self.busy {
            self.status = "busy — wait for the current operation".into();
            return Task::none();
        }
        self.busy = true;
        self.status = "working…".into();
        Task::perform(
            async move {
                match tokio::task::spawn_blocking(f).await {
                    Ok(Ok(s)) => Ok(s),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(e) => Err(e.to_string()),
                }
            },
            Message::OpFinished,
        )
    }

    fn refresh_status(&mut self) -> Task<Message> {
        if self.busy {
            return Task::none();
        }
        self.busy = true;
        self.spawn_status_load()
    }

    fn refresh_status_quiet(&mut self) -> Task<Message> {
        self.spawn_status_load()
    }

    fn spawn_status_load(&self) -> Task<Message> {
        Task::perform(
            async move {
                match tokio::task::spawn_blocking(load_status_rows).await {
                    Ok(Ok(rows)) => Ok(rows),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(e) => Err(e.to_string()),
                }
            },
            Message::StatusLoaded,
        )
    }

    fn status_line(&self) -> String {
        if self.busy {
            format!("working…  {}", self.status)
        } else {
            self.status.clone()
        }
    }

    fn view(&self, id: window::Id) -> Element<'_, Message> {
        match self.surfaces.get(&id).copied() {
            Some(Surface::Menu(menu)) => self.view_menu_window(menu),
            Some(Surface::Dialog(dialog)) => self.view_dialog_window(dialog),
            Some(Surface::Main) => self.view_main(),
            None => {
                if id == self.main_id {
                    self.view_main()
                } else {
                    column![].into()
                }
            }
        }
    }

    fn view_main(&self) -> Element<'_, Message> {
        let page = column![
            self.view_menu_bar(),
            text("Linux file containers  ·  AES-256-XTS").size(12),
            self.view_slots(),
            self.view_volume_row(),
            self.view_actions(),
            checkbox("Never save history", self.never_save_history)
                .on_toggle(Message::NeverSaveHistory),
            Space::with_height(8),
            text(self.status_line()).size(13),
        ]
        .spacing(6)
        .padding(10)
        .width(Length::Fill);

        scrollable(page)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn view_menu_bar(&self) -> Element<'_, Message> {
        row![
            menu_button("Volumes", Menu::Volumes, self.menu_kind(), self.busy),
            menu_button("Tools", Menu::Tools, self.menu_kind(), self.busy),
            bar_button(
                "Help",
                Message::Open(Dialog::About),
                self.current_dialog() == Dialog::About,
                self.busy,
            ),
        ]
        .spacing(4)
        .into()
    }

    fn view_menu_window(&self, menu: Menu) -> Element<'_, Message> {
        let items: &[(&str, Message)] = match menu {
            Menu::Volumes => &[
                ("Create New Volume...", Message::Open(Dialog::Create)),
                ("Mount Volume", Message::Open(Dialog::Mount)),
                ("Dismount Volume", Message::DoDismountSelected),
                ("Dismount All", Message::DoDismountAll),
                ("Change Volume Password...", Message::Open(Dialog::Chpasswd)),
                (
                    "Backup Volume Header...",
                    Message::Open(Dialog::HeaderBackup),
                ),
                (
                    "Restore Volume Header...",
                    Message::Open(Dialog::HeaderRestore),
                ),
                ("Volume Properties...", Message::Open(Dialog::Properties)),
            ],
            Menu::Tools => &[
                ("Benchmark...", Message::Open(Dialog::Benchmark)),
                ("Keyfile Generator...", Message::Open(Dialog::Keyfile)),
                ("Favorite Volumes...", Message::Open(Dialog::Favorites)),
                ("Post-quantum key wrap...", Message::Open(Dialog::Keywrap)),
            ],
        };
        let title = match menu {
            Menu::Volumes => "Volumes",
            Menu::Tools => "Tools",
        };
        let mut col = column![text(title).size(16)]
            .spacing(4)
            .padding(12)
            .width(Length::Fill);
        for (label, msg) in items {
            let mut btn = button(text(*label).size(14))
                .style(button::secondary)
                .padding([6, 10])
                .width(Length::Fill);
            if !self.busy {
                btn = btn.on_press(msg.clone());
            }
            col = col.push(btn);
        }
        col = col.push(Space::with_height(6));
        col = col.push(cmd_button("Close", Message::CloseMenu, false));
        scrollable(col)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn view_slots(&self) -> Element<'_, Message> {
        let header = row![
            cell("Slot", 48.0),
            cell("Volume", 280.0),
            cell("Size", 70.0),
            cell("Encryption", 110.0),
            cell("Type", 90.0),
            cell("Mount Directory", 220.0),
        ]
        .spacing(6);

        let mut list = column![header].spacing(2);
        list = list.push(cmd_button("Refresh", Message::DoStatus, self.busy));

        for n in 1..=SLOT_COUNT {
            list = list.push(self.slot_row(n, self.mount_for_slot(n)));
        }
        for extra in self.status_mounts.iter().filter(|m| !is_slot_id(&m.id)) {
            list = list.push(self.extra_row(extra));
        }

        scrollable(list.spacing(2).width(Length::Fill))
            .height(Length::Fixed(168.0))
            .into()
    }

    fn slot_row(&self, n: u8, mounted: Option<&StatusRow>) -> Element<'_, Message> {
        let (vol, enc, ty, mnt) = if let Some(m) = mounted {
            (
                shorten(&m.container, 36),
                "AES-256-XTS".to_string(),
                type_label(m),
                shorten(&m.mountpoint, 28),
            )
        } else {
            ("—".into(), "—".into(), "—".into(), "—".into())
        };
        let selected = self.selected_slot == n;
        let body = row![
            cell(n.to_string(), 48.0),
            cell(vol, 280.0),
            cell("—", 70.0),
            cell(enc, 110.0),
            cell(ty, 90.0),
            cell(mnt, 220.0),
        ]
        .spacing(6);
        let mut btn = button(body).width(Length::Fill).padding(2);
        btn = if selected {
            btn.style(button::primary)
        } else {
            btn.style(button::secondary)
        };
        if !self.busy {
            btn = btn.on_press(Message::SelectSlot(n));
        }
        btn.into()
    }

    fn extra_row(&self, m: &StatusRow) -> Element<'_, Message> {
        row![
            cell(shorten(&m.id, 8), 48.0),
            cell(shorten(&m.container, 36), 280.0),
            cell("—", 70.0),
            cell("AES-256-XTS", 110.0),
            cell(type_label(m), 90.0),
            cell(shorten(&m.mountpoint, 28), 220.0),
        ]
        .spacing(6)
        .into()
    }

    fn view_volume_row(&self) -> Element<'_, Message> {
        row![
            text("Volume:").width(70),
            text_input("", &self.volume_path)
                .on_input(Message::VolumePath)
                .padding(6)
                .width(Length::Fill),
            cmd_button("Select File...", Message::SelectFile, self.busy),
            cmd_button("Select Device...", Message::SelectDevice, self.busy),
        ]
        .spacing(6)
        .align_y(iced::Alignment::Center)
        .into()
    }

    fn view_actions(&self) -> Element<'_, Message> {
        row![
            cmd_button("Mount", Message::Open(Dialog::Mount), self.busy),
            cmd_button("Dismount", Message::DoDismountSelected, self.busy),
            cmd_button("Create Volume", Message::Open(Dialog::Create), self.busy),
            cmd_button("Auto-Mount Devices", Message::AutoMountDevices, self.busy),
        ]
        .spacing(8)
        .into()
    }

    fn view_dialog_window(&self, dialog: Dialog) -> Element<'_, Message> {
        let body = match dialog {
            Dialog::None => column![].into(),
            Dialog::Mount => self.view_mount_dialog(),
            Dialog::Create => self.view_create_dialog(),
            Dialog::Chpasswd => self.view_chpasswd_dialog(),
            Dialog::HeaderBackup => self.view_header_dialog(true),
            Dialog::HeaderRestore => self.view_header_dialog(false),
            Dialog::Properties => self.view_properties_dialog(),
            Dialog::Favorites => self.view_favorites_dialog(),
            Dialog::Keywrap => self.view_keywrap_dialog(),
            Dialog::Keyfile => self.view_keyfile_dialog(),
            Dialog::Benchmark => self.view_bench_dialog(),
            Dialog::About => self.view_about_dialog(),
            Dialog::Notice => text(&self.notice).size(13).into(),
        };
        let mut page = column![text(dialog_title(dialog)).size(16), body]
            .spacing(8)
            .padding(12)
            .width(Length::Fill);
        if dialog != Dialog::Notice {
            let status = self.status_line();
            if !status.is_empty() {
                page = page.push(text(status).size(13));
            }
        }
        page = page.push(cmd_button("Close", Message::CloseDialog, false));
        scrollable(page)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn view_mount_dialog(&self) -> Element<'_, Message> {
        column![
            text(format!(
                "Slot {}  ·  {}",
                self.selected_slot,
                if self.volume_path.is_empty() {
                    "(no volume selected)"
                } else {
                    self.volume_path.as_str()
                }
            ))
            .size(13),
            text_input("Password", &self.mount_password)
                .secure(true)
                .on_input(Message::MountPassword)
                .padding(6),
            labeled(
                "Keyfiles",
                text_input("optional, comma-separated", &self.mount_keyfile)
                    .on_input(Message::MountKeyfile)
                    .padding(6),
                cmd_button("Keyfiles...", Message::BrowseMountKeyfile, self.busy),
            ),
            labeled(
                "Mount at",
                text_input("directory", &self.mount_point)
                    .on_input(Message::MountPoint)
                    .padding(6),
                cmd_button("Browse", Message::BrowseMountPoint, self.busy),
            ),
            row![
                text("PIM"),
                text_input("0", &self.mount_pim)
                    .on_input(Message::MountPim)
                    .padding(6)
                    .width(80),
                text("(empty or 0 for defaults)"),
                text("PKCS-5 PRF"),
                pick_list(PrfChoice::ALL, Some(self.vc_prf), Message::VcPrf),
                text("Filesystem"),
                pick_list(FsChoice::MOUNT, Some(self.mount_fs), Message::MountFs),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            checkbox("Protect hidden volume", self.mount_protect_hidden)
                .on_toggle(Message::MountProtectHidden),
            checkbox(
                "Live mount (writes through; this window must stay open)",
                self.mount_live,
            )
            .on_toggle(Message::MountLive),
            text_input("Hidden password", &self.mount_hidden_password)
                .secure(true)
                .on_input(Message::MountHiddenPassword)
                .padding(6),
            text("Dismount does not ask for the password again.").size(12),
            cmd_button("OK", Message::DoMount, self.busy),
        ]
        .spacing(6)
        .into()
    }

    fn view_create_dialog(&self) -> Element<'_, Message> {
        column![
            text("Encryption: AES-256-XTS. Password hashing: Argon2id. Header MAC: BLAKE3.")
                .size(12),
            text(if self.volume_path.is_empty() {
                "Choose Select File on the main window, or type a new path in Volume."
            } else {
                "Volume location is the path in the Volume field."
            })
            .size(13),
            text_input("Password", &self.create_password)
                .secure(true)
                .on_input(Message::CreatePassword)
                .padding(6),
            text_input("Confirm password", &self.create_confirm)
                .secure(true)
                .on_input(Message::CreateConfirm)
                .padding(6),
            labeled(
                "Keyfiles",
                text_input("optional", &self.create_keyfile)
                    .on_input(Message::CreateKeyfile)
                    .padding(6),
                cmd_button("Keyfiles...", Message::BrowseCreateKeyfile, self.busy),
            ),
            row![
                text("Size MiB"),
                text_input("16", &self.create_size_mb)
                    .on_input(Message::CreateSize)
                    .padding(6)
                    .width(80),
                text("Filesystem"),
                pick_list(FsChoice::CREATE, Some(self.create_fs), Message::CreateFs),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            row![
                text("Hidden MiB"),
                text_input("0 = none", &self.create_hidden_mb)
                    .on_input(Message::CreateHiddenMb)
                    .padding(6)
                    .width(100),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            text_input("Hidden password", &self.create_hidden_password)
                .secure(true)
                .on_input(Message::CreateHiddenPassword)
                .padding(6),
            checkbox("Wipe data area (slow)", self.create_wipe).on_toggle(Message::CreateWipe),
            cmd_button("Create", Message::DoCreate, self.busy),
        ]
        .spacing(6)
        .into()
    }

    fn view_chpasswd_dialog(&self) -> Element<'_, Message> {
        column![
            text("DC01 only. The master key and ciphertext stay. Take a header backup first.")
                .size(12),
            text_input("Current password", &self.cp_old)
                .secure(true)
                .on_input(Message::CpOld)
                .padding(6),
            text_input("New password", &self.cp_new)
                .secure(true)
                .on_input(Message::CpNew)
                .padding(6),
            text_input("Confirm new password", &self.cp_confirm)
                .secure(true)
                .on_input(Message::CpConfirm)
                .padding(6),
            labeled(
                "Keyfiles",
                text_input("current, optional", &self.cp_keyfile)
                    .on_input(Message::CpKeyfile)
                    .padding(6),
                cmd_button("Browse", Message::BrowseCpKeyfile, self.busy),
            ),
            labeled(
                "New keyfiles",
                text_input("optional, defaults to current", &self.cp_new_keyfile)
                    .on_input(Message::CpNewKeyfile)
                    .padding(6),
                cmd_button("Browse", Message::BrowseCpNewKeyfile, self.busy),
            ),
            cmd_button("OK", Message::DoChpasswd, self.busy),
        ]
        .spacing(6)
        .into()
    }

    fn view_header_dialog(&self, backup: bool) -> Element<'_, Message> {
        let browse = if backup {
            Message::BrowseHdrSave
        } else {
            Message::BrowseHdrOpen
        };
        let go = if backup {
            Message::DoHeaderBackup
        } else {
            Message::DoHeaderRestore
        };
        column![
            text("Primary and hidden header slots only. Volume data is not copied.").size(12),
            labeled(
                "File",
                text_input("header backup", &self.hdr_file)
                    .on_input(Message::HdrFile)
                    .padding(6),
                cmd_button("Browse", browse, self.busy),
            ),
            cmd_button(if backup { "Backup" } else { "Restore" }, go, self.busy),
        ]
        .spacing(6)
        .into()
    }

    fn view_properties_dialog(&self) -> Element<'_, Message> {
        column![
            text(if self.volume_path.is_empty() {
                "Set the volume path on the main window first."
            } else {
                self.volume_path.as_str()
            })
            .size(13),
            text("OK reports the cipher and the password hash that opened this volume.").size(12),
            text_input("Password", &self.info_password)
                .secure(true)
                .on_input(Message::InfoPassword)
                .padding(6),
            labeled(
                "Keyfiles",
                text_input("optional", &self.info_keyfile)
                    .on_input(Message::InfoKeyfile)
                    .padding(6),
                cmd_button("Browse", Message::BrowseInfoKeyfile, self.busy),
            ),
            row![
                text("PIM"),
                text_input("0", &self.info_pim)
                    .on_input(Message::InfoPim)
                    .padding(6)
                    .width(80),
                text("PKCS-5 PRF"),
                pick_list(PrfChoice::ALL, Some(self.vc_prf), Message::VcPrf),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            cmd_button("OK", Message::DoInfo, self.busy),
        ]
        .spacing(6)
        .into()
    }

    fn view_favorites_dialog(&self) -> Element<'_, Message> {
        column![
            text("Passwords are not stored with favorites.").size(12),
            labeled(
                "Path",
                text_input("container", &self.fav_path)
                    .on_input(Message::FavPath)
                    .padding(6),
                cmd_button("Browse", Message::BrowseFavPath, self.busy),
            ),
            text_input("Label", &self.fav_label)
                .on_input(Message::FavLabel)
                .padding(6),
            checkbox("Mount favorite on startup request", self.fav_automount)
                .on_toggle(Message::FavAutomount),
            row![
                cmd_button("List", Message::DoFavList, self.busy),
                cmd_button("Add", Message::DoFavAdd, self.busy),
                cmd_button("Remove", Message::DoFavRemove, self.busy),
            ]
            .spacing(6),
            text(&self.fav_list).size(13),
            self.view_favorite_use_buttons(),
        ]
        .spacing(6)
        .into()
    }

    fn view_favorite_use_buttons(&self) -> Element<'_, Message> {
        let mut col = column![].spacing(2);
        for line in self.fav_list.lines() {
            let mut parts = line.split('\t');
            let label = parts.next().unwrap_or("");
            let path = parts.next().unwrap_or("");
            if path.is_empty() || label.starts_with('(') {
                continue;
            }
            let caption = format!("Use {label}");
            let mut btn = button(text(caption).size(14))
                .style(button::secondary)
                .padding([6, 10]);
            if !self.busy {
                btn = btn.on_press(Message::UseFavorite(path.to_string()));
            }
            col = col.push(btn);
        }
        col.into()
    }

    fn view_keywrap_dialog(&self) -> Element<'_, Message> {
        column![
            text("ML-KEM-768 wraps an exported key. It is not the disk cipher.").size(12),
            labeled(
                "EK",
                text_input("ek.bin", &self.kw_ek)
                    .on_input(Message::KwEk)
                    .padding(6),
                cmd_button("Browse", Message::BrowseKwEk, self.busy),
            ),
            labeled(
                "DK",
                text_input("dk.bin", &self.kw_dk)
                    .on_input(Message::KwDk)
                    .padding(6),
                cmd_button("Browse", Message::BrowseKwDk, self.busy),
            ),
            labeled(
                "In",
                text_input("input", &self.kw_infile)
                    .on_input(Message::KwInfile)
                    .padding(6),
                cmd_button("Browse", Message::BrowseKwIn, self.busy),
            ),
            labeled(
                "Out",
                text_input("output", &self.kw_outfile)
                    .on_input(Message::KwOutfile)
                    .padding(6),
                cmd_button("Browse", Message::BrowseKwOut, self.busy),
            ),
            row![
                cmd_button("Generate keypair", Message::DoKwGen, self.busy),
                cmd_button("Wrap", Message::DoKwWrap, self.busy),
                cmd_button("Unwrap", Message::DoKwUnwrap, self.busy),
            ]
            .spacing(6),
        ]
        .spacing(6)
        .into()
    }

    fn view_keyfile_dialog(&self) -> Element<'_, Message> {
        column![
            text("Random bytes, mode 0600. Not derived from the volume password.").size(12),
            labeled(
                "File",
                text_input("keyfile.bin", &self.kf_path)
                    .on_input(Message::KfPath)
                    .padding(6),
                cmd_button("Browse", Message::BrowseKfPath, self.busy),
            ),
            row![
                text("Bytes"),
                text_input("64", &self.kf_bytes)
                    .on_input(Message::KfBytes)
                    .padding(6)
                    .width(100),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            cmd_button("Generate", Message::DoKeyfile, self.busy),
        ]
        .spacing(6)
        .into()
    }

    fn view_bench_dialog(&self) -> Element<'_, Message> {
        column![
            text("Times Argon2id header-key derivation on this machine. Does not touch a volume.")
                .size(12),
            cmd_button("Time DC01 defaults", Message::DoBenchDc01, self.busy),
            row![
                text("VeraCrypt PIM"),
                text_input("0", &self.bench_pim)
                    .on_input(Message::BenchPim)
                    .padding(6)
                    .width(80),
                cmd_button("Time this PIM", Message::DoBenchPim, self.busy),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            text("PIM 0 is VeraCrypt's default PIM 12 and can take a while.").size(12),
        ]
        .spacing(6)
        .into()
    }

    fn view_about_dialog(&self) -> Element<'_, Message> {
        column![
            text("DeviceCryptor").size(18),
            text("Experimental encrypted containers. Not independently audited.").size(13),
            text("Do not use it for irreplaceable data.").size(13),
            text("Native format DC01: AES-256-XTS, Argon2id, BLAKE3 header MAC.").size(13),
            text("Compat mount: some VeraCrypt/TrueCrypt volumes on the AES-XTS path only.")
                .size(13),
            text("ML-KEM-768 is an optional key-export wrap, not a disk cipher.").size(13),
            text("This window follows the classic VeraCrypt layout. It is not VeraCrypt.").size(13),
            text("Apache-2.0 · Vassbrekke AS").size(12),
        ]
        .spacing(4)
        .into()
    }
}

fn menu_button<'a>(
    label: &'a str,
    menu: Menu,
    open: Option<Menu>,
    busy: bool,
) -> Element<'a, Message> {
    bar_button(label, Message::ToggleMenu(menu), open == Some(menu), busy)
}

fn bar_button<'a>(label: &'a str, msg: Message, active: bool, busy: bool) -> Element<'a, Message> {
    let mut btn = button(text(label).size(14)).padding([4, 10]);
    btn = if active {
        btn.style(button::primary)
    } else {
        btn.style(button::secondary)
    };
    if !busy {
        btn = btn.on_press(msg);
    }
    btn.into()
}

fn dialog_title(dialog: Dialog) -> &'static str {
    match dialog {
        Dialog::None => "DeviceCryptor",
        Dialog::Mount => "Enter Password",
        Dialog::Create => "Volume Creation",
        Dialog::Chpasswd => "Change Password or Keyfiles",
        Dialog::HeaderBackup => "Backup Volume Header",
        Dialog::HeaderRestore => "Restore Volume Header",
        Dialog::Properties => "Volume Properties",
        Dialog::Favorites => "Favorite Volumes",
        Dialog::Keywrap => "Post-quantum key wrap",
        Dialog::Keyfile => "Keyfile Generator",
        Dialog::Benchmark => "Benchmark",
        Dialog::About => "About DeviceCryptor",
        Dialog::Notice => "Notice",
    }
}

fn child_window(width: f32, height: f32) -> window::Settings {
    window::Settings {
        size: Size::new(width, height),
        min_size: Some(Size::new(280.0, 140.0)),
        position: window::Position::Centered,
        ..window::Settings::default()
    }
}

fn menu_window_settings(menu: Menu) -> window::Settings {
    let height = match menu {
        Menu::Volumes => 380.0,
        Menu::Tools => 240.0,
    };
    child_window(340.0, height)
}

fn dialog_window_settings(dialog: Dialog) -> window::Settings {
    let (width, height) = match dialog {
        Dialog::Mount => (680.0, 560.0),
        Dialog::Create => (680.0, 520.0),
        Dialog::Chpasswd => (600.0, 440.0),
        Dialog::HeaderBackup | Dialog::HeaderRestore => (600.0, 240.0),
        Dialog::Properties => (600.0, 400.0),
        Dialog::Favorites => (600.0, 480.0),
        Dialog::Keywrap => (680.0, 420.0),
        Dialog::Keyfile => (560.0, 280.0),
        Dialog::Benchmark => (560.0, 280.0),
        Dialog::About => (560.0, 340.0),
        Dialog::Notice => (520.0, 220.0),
        Dialog::None => (420.0, 180.0),
    };
    child_window(width, height)
}

fn cmd_button<'a>(label: &'a str, msg: Message, busy: bool) -> Element<'a, Message> {
    let btn = button(text(label).size(14))
        .style(button::secondary)
        .padding([6, 10]);
    if busy {
        btn.into()
    } else {
        btn.on_press(msg).into()
    }
}

fn cell<'a>(s: impl Into<String>, width: f32) -> Element<'a, Message> {
    text(s.into()).size(13).width(width).into()
}

fn labeled<'a>(
    label: &'a str,
    field: impl Into<Element<'a, Message>>,
    browse: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    row![text(label).width(90), field.into(), browse.into()]
        .spacing(6)
        .align_y(iced::Alignment::Center)
        .into()
}

fn shorten(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn type_label(m: &StatusRow) -> String {
    let base = if m.backend.is_empty() || m.backend == "fat-checkout" {
        m.fs.clone()
    } else {
        format!("{} {}", m.fs, m.backend)
    };
    if m.session_store == "keyring" {
        format!("{base}·kr")
    } else {
        base
    }
}

fn slot_id(n: u8) -> String {
    format!("slot{n}")
}

fn is_slot_id(id: &str) -> bool {
    id.strip_prefix("slot")
        .and_then(|n| n.parse::<u8>().ok())
        .is_some_and(|n| (1..=SLOT_COUNT).contains(&n))
}

fn default_mountpoint(slot: u8) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    format!("{home}/dc-mnt/slot{slot}")
}

fn load_keyfiles(paths: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for part in paths.split([',', ':']) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        out.push(fs::read(p).map_err(|e| anyhow::anyhow!("read keyfile {p}: {e}"))?);
    }
    Ok(out)
}

fn parse_pim(s: &str) -> anyhow::Result<i32> {
    if s.trim().is_empty() {
        return Ok(0);
    }
    Ok(s.trim().parse()?)
}

fn write_keyfile(path: &std::path::Path, bytes: &str) -> anyhow::Result<String> {
    let n: u32 = bytes
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("bytes must be a number"))?;
    if n == 0 || n > 1024 * 1024 {
        anyhow::bail!("bytes must be 1..=1048576");
    }
    if path.as_os_str().is_empty() {
        anyhow::bail!("path required");
    }
    let mut buf = vec![0u8; n as usize];
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
    Ok(format!("wrote keyfile {} ({} bytes)", path.display(), n))
}

struct CreateSnap {
    path: PathBuf,
    password: String,
    confirm: String,
    size_mb: String,
    fs: FsChoice,
    keyfile: String,
    hidden_mb: String,
    hidden_password: String,
    wipe: bool,
}

impl From<&App> for CreateSnap {
    fn from(a: &App) -> Self {
        Self {
            path: PathBuf::from(&a.volume_path),
            password: a.create_password.clone(),
            confirm: a.create_confirm.clone(),
            size_mb: a.create_size_mb.clone(),
            fs: a.create_fs,
            keyfile: a.create_keyfile.clone(),
            hidden_mb: a.create_hidden_mb.clone(),
            hidden_password: a.create_hidden_password.clone(),
            wipe: a.create_wipe,
        }
    }
}

impl CreateSnap {
    fn run(self) -> anyhow::Result<String> {
        if self.password.is_empty() {
            anyhow::bail!("password required");
        }
        if self.password != self.confirm {
            anyhow::bail!("passwords do not match");
        }
        if self.path.as_os_str().is_empty() {
            anyhow::bail!("set the volume path on the main window first");
        }
        let mb: u64 = if self.size_mb.trim().is_empty() {
            16
        } else {
            self.size_mb.trim().parse()?
        };
        let size = mb.saturating_mul(1024 * 1024).max(2 * 1024 * 1024);
        let kfs = load_keyfiles(&self.keyfile)?;
        let kf_refs: Vec<&[u8]> = kfs.iter().map(|v| v.as_slice()).collect();
        let opts = CreateOptions {
            password: self.password.as_bytes(),
            keyfiles: &kf_refs,
            size,
            sector_size: 512,
            hidden_size: None,
            time_cost: DC01_DEFAULT_TIME,
            memory_kib: DC01_DEFAULT_MEM_KIB,
            parallelism: DC01_DEFAULT_PARALLELISM,
            sparse: !self.wipe,
        };
        let hidden_mb: Option<u64> =
            if self.hidden_mb.trim().is_empty() || self.hidden_mb.trim() == "0" {
                None
            } else {
                Some(self.hidden_mb.trim().parse::<u64>()?)
            };
        if let Some(hmb) = hidden_mb {
            if self.hidden_password.is_empty() {
                anyhow::bail!("hidden password required when hidden size is set");
            }
            let hs = hmb.saturating_mul(1024 * 1024);
            create_container_with_hidden(&self.path, &opts, self.hidden_password.as_bytes(), hs)?;
        } else {
            create_container(&self.path, &opts)?;
        }
        #[cfg(target_os = "linux")]
        {
            let fs_ty = self.fs.as_fs_type();
            if fs_ty != FsType::None {
                let vol = open_container(
                    &self.path,
                    &OpenOptions {
                        password: self.password.as_bytes(),
                        keyfiles: &kf_refs,
                        pim: 0,
                        prf: None,
                        protect_hidden: false,
                        hidden_password: None,
                    },
                )?;
                format_volume(Arc::new(Mutex::new(vol)), fs_ty)?;
                if hidden_mb.is_some() {
                    let hvol = open_container(
                        &self.path,
                        &OpenOptions {
                            password: self.hidden_password.as_bytes(),
                            keyfiles: &kf_refs,
                            pim: 0,
                            prf: None,
                            protect_hidden: false,
                            hidden_password: None,
                        },
                    )?;
                    format_volume(Arc::new(Mutex::new(hvol)), fs_ty)?;
                }
            }
        }
        Ok(format!(
            "created {} (fs={}, wipe={})",
            self.path.display(),
            self.fs.label(),
            self.wipe
        ))
    }
}

struct MountSnap {
    path: PathBuf,
    mountpoint: PathBuf,
    password: String,
    keyfile: String,
    pim: String,
    prf: PrfChoice,
    id: String,
    fs: FsChoice,
    protect_hidden: bool,
    live: bool,
    hidden_password: String,
}

impl From<&App> for MountSnap {
    fn from(a: &App) -> Self {
        Self {
            path: PathBuf::from(&a.volume_path),
            mountpoint: PathBuf::from(&a.mount_point),
            password: a.mount_password.clone(),
            keyfile: a.mount_keyfile.clone(),
            pim: a.mount_pim.clone(),
            prf: a.vc_prf,
            id: slot_id(a.selected_slot),
            fs: a.mount_fs,
            protect_hidden: a.mount_protect_hidden,
            live: a.mount_live,
            hidden_password: a.mount_hidden_password.clone(),
        }
    }
}

impl MountSnap {
    fn run(self) -> anyhow::Result<String> {
        if self.password.is_empty() {
            anyhow::bail!("password required");
        }
        if self.path.as_os_str().is_empty() || self.mountpoint.as_os_str().is_empty() {
            anyhow::bail!("volume and mount directory required");
        }
        let kfs = load_keyfiles(&self.keyfile)?;
        let kf_refs: Vec<&[u8]> = kfs.iter().map(|v| v.as_slice()).collect();
        let pim = parse_pim(&self.pim)?;
        #[cfg(target_os = "linux")]
        {
            let open = OpenOptions {
                password: self.password.as_bytes(),
                keyfiles: &kf_refs,
                pim,
                prf: self.prf.as_prf(),
                protect_hidden: self.protect_hidden,
                hidden_password: if self.protect_hidden {
                    Some(self.hidden_password.as_bytes())
                } else {
                    None
                },
            };
            let st = linux_mount(
                &self.path,
                &LinuxMountOptions {
                    id: &self.id,
                    mountpoint: &self.mountpoint,
                    open,
                    fs_hint: self.fs.as_fs_type(),
                    live: self.live,
                },
            )?;
            Ok(format!(
                "mounted {} → {} (backend={}, encryption={}, hash={}, id={}, session={})",
                self.path.display(),
                self.mountpoint.display(),
                st.backend,
                if st.cipher.is_empty() {
                    "unknown"
                } else {
                    st.cipher.as_str()
                },
                if st.kdf.is_empty() { "unknown" } else { st.kdf.as_str() },
                st.id,
                if st.session_store.is_empty() {
                    "file"
                } else {
                    st.session_store.as_str()
                }
            ))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (kf_refs, pim, self.fs, self.protect_hidden);
            anyhow::bail!("mount is implemented for Linux first");
        }
    }
}

fn run_dismount(id: &str) -> anyhow::Result<String> {
    let id = if id.trim().is_empty() {
        "slot1"
    } else {
        id.trim()
    };
    #[cfg(target_os = "linux")]
    {
        linux_dismount(id)?;
        Ok(format!("dismounted {id}"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = id;
        anyhow::bail!("dismount is implemented for Linux first");
    }
}

fn run_dismount_all() -> anyhow::Result<String> {
    #[cfg(target_os = "linux")]
    {
        let rows = load_status_rows()?;
        if rows.is_empty() {
            return Ok("no volumes mounted".into());
        }
        let n = rows.len();
        for row in rows {
            linux_dismount(&row.id)?;
        }
        Ok(format!("dismounted {n}"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("dismount is implemented for Linux first");
    }
}

fn load_status_rows() -> anyhow::Result<Vec<StatusRow>> {
    #[cfg(target_os = "linux")]
    {
        let states: Vec<MountState> = list_mount_states()?;
        Ok(states
            .into_iter()
            .map(|st| StatusRow {
                id: st.id,
                backend: st.backend,
                container: st.container.display().to_string(),
                mountpoint: st.mountpoint.display().to_string(),
                fs: st.fs,
                session_store: st.session_store,
            })
            .collect())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(Vec::new())
    }
}

struct InfoSnap {
    path: PathBuf,
    password: String,
    keyfile: String,
    pim: String,
    prf: PrfChoice,
}

impl From<&App> for InfoSnap {
    fn from(a: &App) -> Self {
        Self {
            path: PathBuf::from(&a.volume_path),
            password: a.info_password.clone(),
            keyfile: a.info_keyfile.clone(),
            pim: a.info_pim.clone(),
            prf: a.vc_prf,
        }
    }
}

impl InfoSnap {
    fn run(self) -> anyhow::Result<String> {
        if self.password.is_empty() {
            anyhow::bail!("password required");
        }
        if self.path.as_os_str().is_empty() {
            anyhow::bail!("set the volume path on the main window first");
        }
        let kfs = load_keyfiles(&self.keyfile)?;
        let kf_refs: Vec<&[u8]> = kfs.iter().map(|v| v.as_slice()).collect();
        let pim = parse_pim(&self.pim)?;
        let vol = open_container(
            &self.path,
            &OpenOptions {
                password: self.password.as_bytes(),
                keyfiles: &kf_refs,
                pim,
                prf: self.prf.as_prf(),
                protect_hidden: false,
                hidden_password: None,
            },
        )?;
        let msg = format!(
            "kind: {:?}\nhash: {}\nencryption: {}\nsector_size: {}\ndata_offset: {}\ndata_length: {}\nhidden: {}",
            vol.kind,
            vol.kdf,
            vol.cipher.label(),
            vol.sector_size,
            vol.data_offset,
            vol.data_length,
            vol.is_hidden
        );
        dismount_session(vol);
        Ok(msg)
    }
}

struct ChpasswdSnap {
    path: PathBuf,
    old: String,
    new: String,
    confirm: String,
    keyfile: String,
    new_keyfile: String,
}

impl From<&App> for ChpasswdSnap {
    fn from(a: &App) -> Self {
        Self {
            path: PathBuf::from(&a.volume_path),
            old: a.cp_old.clone(),
            new: a.cp_new.clone(),
            confirm: a.cp_confirm.clone(),
            keyfile: a.cp_keyfile.clone(),
            new_keyfile: a.cp_new_keyfile.clone(),
        }
    }
}

impl ChpasswdSnap {
    fn run(self) -> anyhow::Result<String> {
        if self.path.as_os_str().is_empty() {
            anyhow::bail!("set the volume path on the main window first");
        }
        if self.old.is_empty() || self.new.is_empty() {
            anyhow::bail!("current and new passwords required");
        }
        if self.new != self.confirm {
            anyhow::bail!("new passwords do not match");
        }
        let kfs = load_keyfiles(&self.keyfile)?;
        let kf_refs: Vec<&[u8]> = kfs.iter().map(|v| v.as_slice()).collect();
        let new_src = if self.new_keyfile.trim().is_empty() {
            self.keyfile.clone()
        } else {
            self.new_keyfile.clone()
        };
        let new_kfs = load_keyfiles(&new_src)?;
        let new_refs: Vec<&[u8]> = new_kfs.iter().map(|v| v.as_slice()).collect();
        change_password(
            &self.path,
            &OpenOptions {
                password: self.old.as_bytes(),
                keyfiles: &kf_refs,
                pim: 0,
                prf: None,
                protect_hidden: false,
                hidden_password: None,
            },
            self.new.as_bytes(),
            &new_refs,
        )?;
        Ok(format!("password changed on {}", self.path.display()))
    }
}

fn fav_list() -> anyhow::Result<String> {
    let list = list_favorites()?;
    if list.is_empty() {
        return Ok("(no favorites)".into());
    }
    Ok(list
        .into_iter()
        .map(|f| {
            format!(
                "{}\t{}\tautomount={}",
                f.label,
                f.path.display(),
                f.automount
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}
