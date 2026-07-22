//! DeviceCryptor GUI — full parity with the `dc` CLI (iced, no JS).

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use dc_crypto::{
    mlkem_decapsulate_key, mlkem_encapsulate_key, mlkem_generate_keypair, WrappedKey,
};
use dc_format::dc01::{DC01_DEFAULT_MEM_KIB, DC01_DEFAULT_PARALLELISM, DC01_DEFAULT_TIME};
use dc_volume::{
    add_favorite, create_container, create_container_with_hidden, dismount_session, list_favorites,
    open_container, remove_favorite, CreateOptions, Favorite, FsType, OpenOptions,
};
use iced::widget::{
    button, checkbox, column, pick_list, row, scrollable, text, text_input, Space,
};
use iced::{Element, Length, Task, Theme};

#[cfg(target_os = "linux")]
use dc_volume::{format_volume, linux_dismount, linux_mount, LinuxMountOptions};

fn main() -> iced::Result {
    iced::application("DeviceCryptor", App::update, App::view)
        .theme(|_| Theme::Dark)
        .window_size((720.0, 640.0))
        .run_with(|| (App::default(), Task::none()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Tab {
    #[default]
    Create,
    Mount,
    Dismount,
    Info,
    Status,
    Favorites,
    Keywrap,
}

impl Tab {
    const ALL: [Tab; 7] = [
        Tab::Create,
        Tab::Mount,
        Tab::Dismount,
        Tab::Info,
        Tab::Status,
        Tab::Favorites,
        Tab::Keywrap,
    ];

    fn label(self) -> &'static str {
        match self {
            Tab::Create => "Create",
            Tab::Mount => "Mount",
            Tab::Dismount => "Dismount",
            Tab::Info => "Info",
            Tab::Status => "Status",
            Tab::Favorites => "Favorites",
            Tab::Keywrap => "Keywrap",
        }
    }
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
            FsChoice::Fat32 => "fat32",
            FsChoice::Ext4 => "ext4",
            FsChoice::None => "none",
            FsChoice::Auto => "auto",
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

struct App {
    tab: Tab,
    busy: bool,
    status: String,

    // Create
    create_path: String,
    create_password: String,
    create_size_mb: String,
    create_fs: FsChoice,
    create_keyfile: String,
    create_hidden_mb: String,
    create_hidden_password: String,
    create_wipe: bool,

    // Mount
    mount_path: String,
    mount_point: String,
    mount_password: String,
    mount_keyfile: String,
    mount_pim: String,
    mount_id: String,
    mount_fs: FsChoice,
    mount_protect_hidden: bool,
    mount_hidden_password: String,

    // Dismount
    dismount_id: String,
    dismount_password: String,
    dismount_keyfile: String,
    dismount_pim: String,

    // Info
    info_path: String,
    info_password: String,
    info_keyfile: String,
    info_pim: String,

    // Favorites
    fav_path: String,
    fav_label: String,
    fav_automount: bool,
    fav_list: String,

    // Keywrap
    kw_ek: String,
    kw_dk: String,
    kw_infile: String,
    kw_outfile: String,
}

impl Default for App {
    fn default() -> Self {
        Self {
            tab: Tab::Create,
            busy: false,
            status: String::new(),
            create_path: String::new(),
            create_password: String::new(),
            create_size_mb: "16".into(),
            create_fs: FsChoice::Fat32,
            create_keyfile: String::new(),
            create_hidden_mb: String::new(),
            create_hidden_password: String::new(),
            create_wipe: false,
            mount_path: String::new(),
            mount_point: String::new(),
            mount_password: String::new(),
            mount_keyfile: String::new(),
            mount_pim: "0".into(),
            mount_id: "default".into(),
            mount_fs: FsChoice::Auto,
            mount_protect_hidden: false,
            mount_hidden_password: String::new(),
            dismount_id: "default".into(),
            dismount_password: String::new(),
            dismount_keyfile: String::new(),
            dismount_pim: "0".into(),
            info_path: String::new(),
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
        }
    }
}

#[derive(Debug, Clone)]
enum Message {
    Tab(Tab),
    OpFinished(Result<String, String>),

    // Create fields
    CreatePath(String),
    CreatePassword(String),
    CreateSize(String),
    CreateFs(FsChoice),
    CreateKeyfile(String),
    CreateHiddenMb(String),
    CreateHiddenPassword(String),
    CreateWipe(bool),
    BrowseCreatePath,
    BrowseCreateKeyfile,
    DoCreate,

    // Mount
    MountPath(String),
    MountPoint(String),
    MountPassword(String),
    MountKeyfile(String),
    MountPim(String),
    MountId(String),
    MountFs(FsChoice),
    MountProtectHidden(bool),
    MountHiddenPassword(String),
    BrowseMountPath,
    BrowseMountPoint,
    BrowseMountKeyfile,
    DoMount,

    // Dismount
    DismountId(String),
    DismountPassword(String),
    DismountKeyfile(String),
    DismountPim(String),
    BrowseDismountKeyfile,
    DoDismount,

    // Info
    InfoPath(String),
    InfoPassword(String),
    InfoKeyfile(String),
    InfoPim(String),
    BrowseInfoPath,
    BrowseInfoKeyfile,
    DoInfo,

    // Status
    DoStatus,

    // Favorites
    FavPath(String),
    FavLabel(String),
    FavAutomount(bool),
    BrowseFavPath,
    DoFavList,
    DoFavAdd,
    DoFavRemove,

    // Keywrap
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
}

impl App {
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tab(t) => {
                self.tab = t;
                if t == Tab::Favorites {
                    return self.run_op(|| fav_list());
                }
                if t == Tab::Status {
                    return self.run_op(|| status_list());
                }
            }
            Message::OpFinished(res) => {
                self.busy = false;
                match res {
                    Ok(s) => {
                        if self.tab == Tab::Favorites {
                            self.fav_list = s.clone();
                        }
                        // Drop secrets from UI state after success (not logged).
                        match self.tab {
                            Tab::Create => {
                                self.create_password.clear();
                                self.create_hidden_password.clear();
                            }
                            Tab::Mount => {
                                self.mount_password.clear();
                                self.mount_hidden_password.clear();
                            }
                            Tab::Dismount => self.dismount_password.clear(),
                            Tab::Info => self.info_password.clear(),
                            _ => {}
                        }
                        self.status = s;
                    }
                    Err(e) => self.status = format!("error: {e}"),
                }
            }

            Message::CreatePath(v) => self.create_path = v,
            Message::CreatePassword(v) => self.create_password = v,
            Message::CreateSize(v) => self.create_size_mb = v,
            Message::CreateFs(v) => self.create_fs = v,
            Message::CreateKeyfile(v) => self.create_keyfile = v,
            Message::CreateHiddenMb(v) => self.create_hidden_mb = v,
            Message::CreateHiddenPassword(v) => self.create_hidden_password = v,
            Message::CreateWipe(v) => self.create_wipe = v,
            Message::BrowseCreatePath => {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("New container")
                    .save_file()
                {
                    self.create_path = p.display().to_string();
                }
            }
            Message::BrowseCreateKeyfile => {
                if let Some(p) = rfd::FileDialog::new().set_title("Keyfile").pick_file() {
                    self.create_keyfile = p.display().to_string();
                }
            }
            Message::DoCreate => {
                let snap = CreateSnap::from(&*self);
                return self.run_op(move || snap.run());
            }

            Message::MountPath(v) => self.mount_path = v,
            Message::MountPoint(v) => self.mount_point = v,
            Message::MountPassword(v) => self.mount_password = v,
            Message::MountKeyfile(v) => self.mount_keyfile = v,
            Message::MountPim(v) => self.mount_pim = v,
            Message::MountId(v) => self.mount_id = v,
            Message::MountFs(v) => self.mount_fs = v,
            Message::MountProtectHidden(v) => self.mount_protect_hidden = v,
            Message::MountHiddenPassword(v) => self.mount_hidden_password = v,
            Message::BrowseMountPath => {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("Container")
                    .pick_file()
                {
                    self.mount_path = p.display().to_string();
                }
            }
            Message::BrowseMountPoint => {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("Mountpoint directory")
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

            Message::DismountId(v) => self.dismount_id = v,
            Message::DismountPassword(v) => self.dismount_password = v,
            Message::DismountKeyfile(v) => self.dismount_keyfile = v,
            Message::DismountPim(v) => self.dismount_pim = v,
            Message::BrowseDismountKeyfile => {
                if let Some(p) = rfd::FileDialog::new().set_title("Keyfile").pick_file() {
                    self.dismount_keyfile = p.display().to_string();
                }
            }
            Message::DoDismount => {
                let snap = DismountSnap::from(&*self);
                return self.run_op(move || snap.run());
            }

            Message::InfoPath(v) => self.info_path = v,
            Message::InfoPassword(v) => self.info_password = v,
            Message::InfoKeyfile(v) => self.info_keyfile = v,
            Message::InfoPim(v) => self.info_pim = v,
            Message::BrowseInfoPath => {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("Container")
                    .pick_file()
                {
                    self.info_path = p.display().to_string();
                }
            }
            Message::BrowseInfoKeyfile => {
                if let Some(p) = rfd::FileDialog::new().set_title("Keyfile").pick_file() {
                    self.info_keyfile = p.display().to_string();
                }
            }
            Message::DoInfo => {
                let snap = InfoSnap::from(&*self);
                return self.run_op(move || snap.run());
            }

            Message::DoStatus => return self.run_op(|| status_list()),

            Message::FavPath(v) => self.fav_path = v,
            Message::FavLabel(v) => self.fav_label = v,
            Message::FavAutomount(v) => self.fav_automount = v,
            Message::BrowseFavPath => {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("Container")
                    .pick_file()
                {
                    self.fav_path = p.display().to_string();
                }
            }
            Message::DoFavList => return self.run_op(|| fav_list()),
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
        }
        Task::none()
    }

    fn run_op<F>(&mut self, f: F) -> Task<Message>
    where
        F: FnOnce() -> anyhow::Result<String> + Send + 'static,
    {
        if self.busy {
            self.status = "busy — wait for current operation".into();
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

    fn view(&self) -> Element<'_, Message> {
        let tabs = row(Tab::ALL.iter().map(|t| {
            let label = t.label();
            let btn = if *t == self.tab {
                button(text(label)).on_press(Message::Tab(*t))
            } else {
                button(text(label)).style(iced::widget::button::secondary).on_press(Message::Tab(*t))
            };
            btn.into()
        }))
        .spacing(6)
        .wrap();

        let body: Element<'_, Message> = match self.tab {
            Tab::Create => self.view_create(),
            Tab::Mount => self.view_mount(),
            Tab::Dismount => self.view_dismount(),
            Tab::Info => self.view_info(),
            Tab::Status => self.view_status(),
            Tab::Favorites => self.view_favorites(),
            Tab::Keywrap => self.view_keywrap(),
        };

        let busy = if self.busy {
            text("Status: working…")
        } else {
            text("Status:")
        };

        scrollable(
            column![
                text("DeviceCryptor").size(28),
                text("AES-256-XTS · Argon2id · DC01 — GUI parity with `dc` CLI").size(13),
                Space::with_height(8),
                tabs,
                Space::with_height(12),
                body,
                Space::with_height(12),
                busy,
                text(&self.status),
            ]
            .spacing(8)
            .padding(20)
            .width(Length::Fill),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    fn view_create(&self) -> Element<'_, Message> {
        column![
            labeled_row(
                "Container",
                text_input("path.dc", &self.create_path)
                    .on_input(Message::CreatePath)
                    .padding(8),
                button("Browse").on_press(Message::BrowseCreatePath),
            ),
            text_input("Password", &self.create_password)
                .secure(true)
                .on_input(Message::CreatePassword)
                .padding(8),
            labeled_row(
                "Keyfile",
                text_input("optional, comma-separated", &self.create_keyfile)
                    .on_input(Message::CreateKeyfile)
                    .padding(8),
                button("Browse").on_press(Message::BrowseCreateKeyfile),
            ),
            row![
                text("Size MiB"),
                text_input("16", &self.create_size_mb)
                    .on_input(Message::CreateSize)
                    .padding(8)
                    .width(100),
                text("FS"),
                pick_list(
                    FsChoice::CREATE,
                    Some(self.create_fs),
                    Message::CreateFs
                ),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            row![
                text("Hidden MiB"),
                text_input("0 = none", &self.create_hidden_mb)
                    .on_input(Message::CreateHiddenMb)
                    .padding(8)
                    .width(120),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            text_input("Hidden password", &self.create_hidden_password)
                .secure(true)
                .on_input(Message::CreateHiddenPassword)
                .padding(8),
            checkbox("Wipe data area (slow)", self.create_wipe).on_toggle(Message::CreateWipe),
            button("Create volume").on_press(Message::DoCreate),
        ]
        .spacing(8)
        .into()
    }

    fn view_mount(&self) -> Element<'_, Message> {
        column![
            labeled_row(
                "Container",
                text_input("path.dc", &self.mount_path)
                    .on_input(Message::MountPath)
                    .padding(8),
                button("Browse").on_press(Message::BrowseMountPath),
            ),
            labeled_row(
                "Mountpoint",
                text_input("./mnt", &self.mount_point)
                    .on_input(Message::MountPoint)
                    .padding(8),
                button("Browse").on_press(Message::BrowseMountPoint),
            ),
            text_input("Password", &self.mount_password)
                .secure(true)
                .on_input(Message::MountPassword)
                .padding(8),
            labeled_row(
                "Keyfile",
                text_input("optional, comma-separated", &self.mount_keyfile)
                    .on_input(Message::MountKeyfile)
                    .padding(8),
                button("Browse").on_press(Message::BrowseMountKeyfile),
            ),
            row![
                text("Mount ID"),
                text_input("default", &self.mount_id)
                    .on_input(Message::MountId)
                    .padding(8)
                    .width(140),
                text("PIM"),
                text_input("0", &self.mount_pim)
                    .on_input(Message::MountPim)
                    .padding(8)
                    .width(80),
                text("FS"),
                pick_list(FsChoice::MOUNT, Some(self.mount_fs), Message::MountFs),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            checkbox("Protect hidden volume", self.mount_protect_hidden)
                .on_toggle(Message::MountProtectHidden),
            text_input("Hidden password (if protecting)", &self.mount_hidden_password)
                .secure(true)
                .on_input(Message::MountHiddenPassword)
                .padding(8),
            button("Mount").on_press(Message::DoMount),
            text("Linux FAT mounts use checkout/checkin — dismount to sync writes.").size(12),
        ]
        .spacing(8)
        .into()
    }

    fn view_dismount(&self) -> Element<'_, Message> {
        column![
            row![
                text("Mount ID"),
                text_input("default", &self.dismount_id)
                    .on_input(Message::DismountId)
                    .padding(8)
                    .width(160),
                text("PIM"),
                text_input("0", &self.dismount_pim)
                    .on_input(Message::DismountPim)
                    .padding(8)
                    .width(80),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            text_input("Password", &self.dismount_password)
                .secure(true)
                .on_input(Message::DismountPassword)
                .padding(8),
            labeled_row(
                "Keyfile",
                text_input("optional, comma-separated", &self.dismount_keyfile)
                    .on_input(Message::DismountKeyfile)
                    .padding(8),
                button("Browse").on_press(Message::BrowseDismountKeyfile),
            ),
            button("Dismount / sync").on_press(Message::DoDismount),
        ]
        .spacing(8)
        .into()
    }

    fn view_info(&self) -> Element<'_, Message> {
        column![
            labeled_row(
                "Container",
                text_input("path.dc", &self.info_path)
                    .on_input(Message::InfoPath)
                    .padding(8),
                button("Browse").on_press(Message::BrowseInfoPath),
            ),
            text_input("Password", &self.info_password)
                .secure(true)
                .on_input(Message::InfoPassword)
                .padding(8),
            labeled_row(
                "Keyfile",
                text_input("optional, comma-separated", &self.info_keyfile)
                    .on_input(Message::InfoKeyfile)
                    .padding(8),
                button("Browse").on_press(Message::BrowseInfoKeyfile),
            ),
            row![
                text("PIM"),
                text_input("0", &self.info_pim)
                    .on_input(Message::InfoPim)
                    .padding(8)
                    .width(80),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            button("Show info").on_press(Message::DoInfo),
        ]
        .spacing(8)
        .into()
    }

    fn view_status(&self) -> Element<'_, Message> {
        column![
            button("Refresh mounts").on_press(Message::DoStatus),
            text("Active mounts appear in Status below after refresh."),
        ]
        .spacing(8)
        .into()
    }

    fn view_favorites(&self) -> Element<'_, Message> {
        column![
            labeled_row(
                "Path",
                text_input("container", &self.fav_path)
                    .on_input(Message::FavPath)
                    .padding(8),
                button("Browse").on_press(Message::BrowseFavPath),
            ),
            text_input("Label", &self.fav_label)
                .on_input(Message::FavLabel)
                .padding(8),
            checkbox("Automount", self.fav_automount).on_toggle(Message::FavAutomount),
            row![
                button("List").on_press(Message::DoFavList),
                button("Add").on_press(Message::DoFavAdd),
                button("Remove").on_press(Message::DoFavRemove),
            ]
            .spacing(8),
            text("Favorites:"),
            text(&self.fav_list),
        ]
        .spacing(8)
        .into()
    }

    fn view_keywrap(&self) -> Element<'_, Message> {
        column![
            text("ML-KEM-768 key wrap (export path)").size(16),
            labeled_row(
                "EK",
                text_input("ek.bin", &self.kw_ek)
                    .on_input(Message::KwEk)
                    .padding(8),
                button("Browse").on_press(Message::BrowseKwEk),
            ),
            labeled_row(
                "DK",
                text_input("dk.bin", &self.kw_dk)
                    .on_input(Message::KwDk)
                    .padding(8),
                button("Browse").on_press(Message::BrowseKwDk),
            ),
            labeled_row(
                "In",
                text_input("input", &self.kw_infile)
                    .on_input(Message::KwInfile)
                    .padding(8),
                button("Browse").on_press(Message::BrowseKwIn),
            ),
            labeled_row(
                "Out",
                text_input("output", &self.kw_outfile)
                    .on_input(Message::KwOutfile)
                    .padding(8),
                button("Browse").on_press(Message::BrowseKwOut),
            ),
            row![
                button("Generate keypair").on_press(Message::DoKwGen),
                button("Wrap").on_press(Message::DoKwWrap),
                button("Unwrap").on_press(Message::DoKwUnwrap),
            ]
            .spacing(8),
        ]
        .spacing(8)
        .into()
    }
}

fn labeled_row<'a>(
    label: &'a str,
    field: impl Into<Element<'a, Message>>,
    browse: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    row![text(label).width(90), field.into(), browse.into()]
        .spacing(8)
        .align_y(iced::Alignment::Center)
        .into()
}

/// Load keyfiles. Paths may be comma- or colon-separated (CLI allows repeated `--keyfile`).
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

struct CreateSnap {
    path: PathBuf,
    password: String,
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
            path: PathBuf::from(&a.create_path),
            password: a.create_password.clone(),
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
        if self.path.as_os_str().is_empty() {
            anyhow::bail!("path required");
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

        let hidden_mb: Option<u64> = if self.hidden_mb.trim().is_empty() || self.hidden_mb.trim() == "0"
        {
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
    id: String,
    fs: FsChoice,
    protect_hidden: bool,
    hidden_password: String,
}

impl From<&App> for MountSnap {
    fn from(a: &App) -> Self {
        Self {
            path: PathBuf::from(&a.mount_path),
            mountpoint: PathBuf::from(&a.mount_point),
            password: a.mount_password.clone(),
            keyfile: a.mount_keyfile.clone(),
            pim: a.mount_pim.clone(),
            id: a.mount_id.clone(),
            fs: a.mount_fs,
            protect_hidden: a.mount_protect_hidden,
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
            anyhow::bail!("container and mountpoint required");
        }
        let kfs = load_keyfiles(&self.keyfile)?;
        let kf_refs: Vec<&[u8]> = kfs.iter().map(|v| v.as_slice()).collect();
        let pim = parse_pim(&self.pim)?;
        let id = if self.id.trim().is_empty() {
            "default".into()
        } else {
            self.id
        };

        #[cfg(target_os = "linux")]
        {
            let open = OpenOptions {
                password: self.password.as_bytes(),
                keyfiles: &kf_refs,
                pim,
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
                    id: &id,
                    mountpoint: &self.mountpoint,
                    open,
                    fs_hint: self.fs.as_fs_type(),
                },
            )?;
            Ok(format!(
                "mounted {} → {} (backend={}, id={})",
                self.path.display(),
                self.mountpoint.display(),
                st.backend,
                st.id
            ))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (kf_refs, pim, id, self.fs, self.protect_hidden);
            anyhow::bail!("mount is implemented for Linux first");
        }
    }
}

struct DismountSnap {
    id: String,
    password: String,
    keyfile: String,
    pim: String,
}

impl From<&App> for DismountSnap {
    fn from(a: &App) -> Self {
        Self {
            id: a.dismount_id.clone(),
            password: a.dismount_password.clone(),
            keyfile: a.dismount_keyfile.clone(),
            pim: a.dismount_pim.clone(),
        }
    }
}

impl DismountSnap {
    fn run(self) -> anyhow::Result<String> {
        if self.password.is_empty() {
            anyhow::bail!("password required");
        }
        let id = if self.id.trim().is_empty() {
            "default".into()
        } else {
            self.id
        };
        let kfs = load_keyfiles(&self.keyfile)?;
        let kf_refs: Vec<&[u8]> = kfs.iter().map(|v| v.as_slice()).collect();
        let pim = parse_pim(&self.pim)?;
        #[cfg(target_os = "linux")]
        {
            linux_dismount(
                &id,
                OpenOptions {
                    password: self.password.as_bytes(),
                    keyfiles: &kf_refs,
                    pim,
                    protect_hidden: false,
                    hidden_password: None,
                },
            )?;
            Ok(format!("dismounted {id}"))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (kf_refs, pim);
            anyhow::bail!("dismount is implemented for Linux first");
        }
    }
}

struct InfoSnap {
    path: PathBuf,
    password: String,
    keyfile: String,
    pim: String,
}

impl From<&App> for InfoSnap {
    fn from(a: &App) -> Self {
        Self {
            path: PathBuf::from(&a.info_path),
            password: a.info_password.clone(),
            keyfile: a.info_keyfile.clone(),
            pim: a.info_pim.clone(),
        }
    }
}

impl InfoSnap {
    fn run(self) -> anyhow::Result<String> {
        if self.password.is_empty() {
            anyhow::bail!("password required");
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
                protect_hidden: false,
                hidden_password: None,
            },
        )?;
        let msg = format!(
            "kind: {:?}\nsector_size: {}\ndata_offset: {}\ndata_length: {}\nhidden: {}",
            vol.kind, vol.sector_size, vol.data_offset, vol.data_length, vol.is_hidden
        );
        dismount_session(vol);
        Ok(msg)
    }
}

fn status_list() -> anyhow::Result<String> {
    #[cfg(target_os = "linux")]
    {
        let dir = dc_platform::default_mount_state_dir()?;
        if !dir.exists() {
            return Ok("(no mounts)".into());
        }
        let mut lines = Vec::new();
        for e in fs::read_dir(dir)? {
            let e = e?;
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let data = fs::read_to_string(&p)?;
            if let Ok(st) = serde_json::from_str::<dc_volume::MountState>(&data) {
                lines.push(format!(
                    "{}\t{}\t{}\t{}",
                    st.id,
                    st.backend,
                    st.container.display(),
                    st.mountpoint.display()
                ));
            }
        }
        if lines.is_empty() {
            Ok("(no mounts)".into())
        } else {
            Ok(lines.join("\n"))
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok("(status available on Linux)".into())
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
