// ═════════════════════════════════════════════════════════════════════════════
//  TUN MODE  (Windows only)
// ═════════════════════════════════════════════════════════════════════════════

use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;
use tokio::process::Command as AsyncCommand;
use tokio::time::{sleep, Duration};

const TUN2SOCKS_URL: &str =
    "https://github.com/xjasonlyu/tun2socks/releases/latest/download/tun2socks-windows-amd64.zip";
const WINTUN_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";
const TUN_ADAPTER_NAME: &str = "wstunnel";
const DIRECT_DNS: &str = "8.8.8.8";

pub struct TunConfig {
    pub socks_addr: String,
    pub tun_addr: Ipv4Addr,
    pub tun_mask: Ipv4Addr,
    pub real_gateway: Option<String>,
    pub server_host: String,
    pub bin_dir: PathBuf,
}

impl TunConfig {
    pub fn new(socks_addr: &str, server_host: &str) -> Self {
        TunConfig {
            socks_addr: socks_addr.to_string(),
            tun_addr: Ipv4Addr::new(198, 18, 0, 1),
            tun_mask: Ipv4Addr::new(255, 255, 0, 0),
            real_gateway: None,
            server_host: server_host.to_string(),
            bin_dir: PathBuf::from("."),
        }
    }
}

#[cfg(target_os = "windows")]
pub async fn run_tun_mode(cfg: TunConfig) -> Result<()> {
    println!("[TUN] Запуск прозрачного прокси режима");
    println!("[TUN] TCP (HTTP, HTTPS, WebSocket) → туннель");
    println!("[TUN] UDP → напрямую (DNS работает без туннеля)");
    println!();

    let tun2socks_path = ensure_tun2socks(&cfg.bin_dir).await?;
    let wintun_dll = ensure_wintun(&cfg.bin_dir).await?;

    // Получаем абсолютные пути — критично для корректной работы
    let tun2socks_abs = tun2socks_path
        .canonicalize()
        .unwrap_or_else(|_| tun2socks_path.clone());
    let wintun_abs = wintun_dll
        .canonicalize()
        .unwrap_or_else(|_| wintun_dll.clone());

    println!("[TUN] tun2socks: {}", tun2socks_abs.display());
    println!("[TUN] wintun.dll: {}", wintun_abs.display());

    // wintun.dll ДОЛЖНА лежать в той же директории что и tun2socks.exe
    let tun2socks_dir = tun2socks_abs
        .parent()
        .context("Не удалось определить директорию tun2socks.exe")?;
    let dll_beside_tun2socks = tun2socks_dir.join("wintun.dll");

    // Копируем только если wintun.dll и tun2socks.exe в разных папках
    if dll_beside_tun2socks.canonicalize().unwrap_or_default() != wintun_abs {
        println!(
            "[TUN] Копирование wintun.dll → {}",
            dll_beside_tun2socks.display()
        );
        std::fs::copy(&wintun_abs, &dll_beside_tun2socks).context(format!(
            "Не удалось скопировать wintun.dll в {}",
            dll_beside_tun2socks.display()
        ))?;
        println!("[TUN] ✓ wintun.dll скопирована рядом с tun2socks.exe");
    } else {
        println!("[TUN] ✓ wintun.dll уже рядом с tun2socks.exe");
    }

    let gateway = match &cfg.real_gateway {
        Some(gw) => gw.clone(),
        None => detect_gateway().await?,
    };
    println!("[TUN] Реальный шлюз: {}", gateway);

    let server_ip = resolve_host(&cfg.server_host).await?;
    println!("[TUN] IP VPS: {} → прямой маршрут", server_ip);

    // ВАЖНО: прямые маршруты ДО изменения дефолтного
    add_route(&server_ip, "255.255.255.255", &gateway)?;
    add_route(DIRECT_DNS, "255.255.255.255", &gateway)?;
    add_route("8.8.4.4", "255.255.255.255", &gateway)?;
    println!("[TUN] Прямые маршруты добавлены: VPS + DNS");

    println!("[TUN] Запуск tun2socks...");
    let mut proc = start_tun2socks(&tun2socks_abs, &cfg).await?;

    println!("[TUN] Ожидание инициализации адаптера (5 сек)...");
    sleep(Duration::from_secs(5)).await;

    if let Ok(Some(code)) = proc.try_wait() {
        cleanup_routes(&server_ip)?;
        anyhow::bail!(
            "tun2socks завершился преждевременно (код: {})\n\
             Проверьте:\n\
             1. wintun.dll рядом с tun2socks.exe: {}\n\
             2. Запуск от Администратора\n\
             3. Нет другого WinTUN адаптера с именем '{}'",
            code,
            dll_beside_tun2socks.display(),
            TUN_ADAPTER_NAME
        );
    }

    setup_tun_routes(&cfg.tun_addr.to_string()).await?;
    setup_dns().await;

    println!();
    println!("[TUN] ✓ Прозрачный прокси активен — WebSocket, HTTPS, HTTP через туннель");
    println!("[TUN] Ctrl+C — остановить и восстановить маршруты");
    println!();

    let server_ip_c = server_ip.clone();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => { println!("\n[TUN] Остановка..."); }
        s = proc.wait() => { eprintln!("\n[TUN] tun2socks завершился: {:?}", s); }
    }

    cleanup_routes(&server_ip_c)?;
    restore_dns();
    println!("[TUN] Маршруты восстановлены");
    Ok(())
}

#[cfg(target_os = "windows")]
async fn start_tun2socks(
    tun2socks_abs: &PathBuf,
    cfg: &TunConfig,
) -> Result<tokio::process::Child> {
    let post_up = format!(
        "netsh interface ip set address \"{}\" static {} {} none",
        TUN_ADAPTER_NAME, cfg.tun_addr, cfg.tun_mask,
    );
    let work_dir = tun2socks_abs.parent().unwrap();

    // Пробуем device string по порядку пока один не заработает.
    // ВАЖНО: правильный формат — "tun://" (не "wintun://", не "gvisor://")
    // tun2socks v2 использует wintun.dll через драйвер "tun"
    let drivers: &[&str] = &[
        "tun",    // правильный driver string для tun2socks v2 + wintun.dll
        "wintun", // альтернатива для некоторых версий
        "gvisor", // fallback без dll
    ];

    for driver in drivers {
        let device = format!("{}://{}", driver, TUN_ADAPTER_NAME);
        println!("[TUN] post-up: {}", post_up);
        println!("[TUN] Запуск tun2socks, device: {}", device);

        let mut child = match AsyncCommand::new(tun2socks_abs)
            .current_dir(work_dir)
            .arg("-device")
            .arg(&device)
            .arg("-proxy")
            .arg(format!("socks5://{}", cfg.socks_addr))
            .arg("-loglevel")
            .arg("silent") // полностью отключить логи tun2socks
            .arg("-tcp-auto-tuning")
            .arg("-tun-post-up")
            .arg(&post_up)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[TUN] spawn failed: {}", e);
                continue;
            }
        };

        println!("[TUN] tun2socks PID={:?}", child.id());
        tokio::time::sleep(Duration::from_secs(2)).await;

        match child.try_wait() {
            Ok(None) => {
                println!("[TUN] driver '{}' работает", driver);
                return Ok(child);
            }
            Ok(Some(code)) => {
                eprintln!(
                    "[TUN] driver '{}' не поддерживается ({}), пробуем следующий...",
                    driver, code
                );
            }
            Err(e) => eprintln!("[TUN] wait error: {}", e),
        }
    }

    anyhow::bail!(
        "Ни один драйвер tun2socks не запустился.\n\
         Возможные причины:\n\
         1. Запуск не от Администратора\n\
         2. Windows Defender блокирует wintun.dll — добавьте папку в исключения\n\
         3. Попробуйте другую версию tun2socks: https://github.com/xjasonlyu/tun2socks/releases\n\
         4. Установите Visual C++ Redistributable 2019+"
    )
}

#[cfg(target_os = "windows")]
async fn setup_tun_routes(tun_gw: &str) -> Result<()> {
    println!("[TUN] Настройка маршрутов через TUN...");
    for (net, mask) in &[("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
        let ok = Command::new("route")
            .args(["add", net, "mask", mask, tun_gw, "metric", "5"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            println!("[TUN] route add {}/{} via {} — OK", net, mask, tun_gw);
        } else {
            eprintln!("[TUN] route {}/{} — уже существует или ошибка", net, mask);
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn setup_dns() {
    let ok = Command::new("netsh")
        .args([
            "interface",
            "ip",
            "set",
            "dnsservers",
            &format!("name={}", TUN_ADAPTER_NAME),
            "source=static",
            &format!("address={}", DIRECT_DNS),
            "validate=no",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    println!(
        "[TUN] DNS: {} ({})",
        DIRECT_DNS,
        if ok {
            "OK"
        } else {
            "предупреждение — не критично"
        }
    );
}

#[cfg(target_os = "windows")]
fn restore_dns() {
    let _ = Command::new("netsh")
        .args([
            "interface",
            "ip",
            "set",
            "dnsservers",
            &format!("name={}", TUN_ADAPTER_NAME),
            "source=dhcp",
            "validate=no",
        ])
        .status();
}

#[cfg(target_os = "windows")]
fn cleanup_routes(server_ip: &str) -> Result<()> {
    for (net, mask) in &[("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
        let _ = Command::new("route")
            .args(["delete", net, "mask", mask])
            .status();
    }
    for ip in &[server_ip, DIRECT_DNS, "8.8.4.4"] {
        let _ = Command::new("route").args(["delete", ip]).status();
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn add_route(dest: &str, mask: &str, gateway: &str) -> Result<()> {
    let ok = Command::new("route")
        .args(["add", dest, "mask", mask, gateway])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!(
            "[TUN] Маршрут {} уже существует или ошибка (не критично)",
            dest
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn detect_gateway() -> Result<String> {
    let out = AsyncCommand::new("powershell")
        .args([
            "-NoProfile", "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
        ])
        .output().await.context("PowerShell недоступен")?;

    let gw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !gw.is_empty() && gw != "0.0.0.0" {
        return Ok(gw);
    }

    let out2 = AsyncCommand::new("cmd")
        .args(["/C", "route print 0.0.0.0 mask 0.0.0.0"])
        .output()
        .await?;
    for line in String::from_utf8_lossy(&out2.stdout).lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() >= 3
            && p[0] == "0.0.0.0"
            && p[1] == "0.0.0.0"
            && p[2] != "0.0.0.0"
            && p[2].contains('.')
        {
            return Ok(p[2].to_string());
        }
    }
    anyhow::bail!("Не удалось определить шлюз. Укажите вручную: --gateway 192.168.0.1")
}

async fn resolve_host(host: &str) -> Result<String> {
    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(host.to_string());
    }
    let hostname = host.split(':').next().unwrap_or(host);
    for addr in tokio::net::lookup_host(format!("{}:80", hostname))
        .await
        .context(format!("DNS резолвинг {}", hostname))?
    {
        if let std::net::IpAddr::V4(ip) = addr.ip() {
            return Ok(ip.to_string());
        }
    }
    anyhow::bail!("Нет IPv4 для {}", hostname)
}

#[cfg(target_os = "windows")]
async fn ensure_tun2socks(bin_dir: &PathBuf) -> Result<PathBuf> {
    let p = bin_dir.join("tun2socks.exe");
    if p.exists() {
        println!("[TUN] tun2socks найден: {}", p.display());
        return Ok(p);
    }
    println!("[TUN] Загрузка tun2socks...");
    download_zip(
        TUN2SOCKS_URL,
        bin_dir,
        "tun2socks-windows-amd64.exe",
        "tun2socks.exe",
    )
    .await?;
    if !p.exists() {
        anyhow::bail!(
            "tun2socks.exe не найден. Скачайте вручную:\n{}",
            TUN2SOCKS_URL
        );
    }
    Ok(p)
}

#[cfg(target_os = "windows")]
async fn ensure_wintun(bin_dir: &PathBuf) -> Result<PathBuf> {
    let p = bin_dir.join("wintun.dll");
    if p.exists() {
        println!("[TUN] wintun.dll найден: {}", p.display());
        return Ok(p);
    }
    println!("[TUN] Загрузка WinTUN...");
    download_zip(
        WINTUN_URL,
        bin_dir,
        "wintun/bin/amd64/wintun.dll",
        "wintun.dll",
    )
    .await?;
    if !p.exists() {
        anyhow::bail!("wintun.dll не найден. Скачайте вручную:\n{}", WINTUN_URL);
    }
    Ok(p)
}

#[cfg(target_os = "windows")]
async fn download_zip(
    url: &str,
    dest_dir: &PathBuf,
    file_in_zip: &str,
    out_name: &str,
) -> Result<()> {
    let bytes = reqwest::get(url)
        .await
        .context(format!("GET {}", url))?
        .bytes()
        .await
        .context("Чтение тела")?;
    println!("[TUN] Загружено {} KB", bytes.len() / 1024);

    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("Открытие ZIP")?;
    let suffix = std::path::Path::new(file_in_zip)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();

    for i in 0..archive.len() {
        let mut f = archive.by_index(i).unwrap();
        let name = f.name().to_string();
        if name.ends_with(file_in_zip) || name.ends_with(suffix) {
            let out = dest_dir.join(out_name);
            std::io::copy(
                &mut f,
                &mut std::fs::File::create(&out).context(format!("Создание {}", out.display()))?,
            )
            .context("Запись файла")?;
            println!("[TUN] ✓ {} → {}", name, out.display());
            return Ok(());
        }
    }
    anyhow::bail!("'{}' не найден в архиве {}", file_in_zip, url)
}

#[cfg(not(target_os = "windows"))]
pub async fn run_tun_mode(cfg: TunConfig) -> Result<()> {
    println!("[TUN] Linux:");
    println!("  ip tuntap add mode tun dev tun0");
    println!("  ip addr add 198.18.0.1/16 dev tun0 && ip link set tun0 up");
    println!(
        "  tun2socks -device tun://tun0 -proxy socks5://{} -udp-timeout 0",
        cfg.socks_addr
    );
    println!("  ip route add default via 198.18.0.1 dev tun0 table 100");
    println!("  ip rule add not fwmark 1 table 100");
    Ok(())
}
