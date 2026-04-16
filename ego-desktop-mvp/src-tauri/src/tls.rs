use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
            ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose};
use std::path::PathBuf;
use std::sync::OnceLock;

fn tls_dir() -> PathBuf {
    let dir = crate::ledger::base_data_dir().join("tls");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub static HTTPS_PORT: OnceLock<u16> = OnceLock::new();

pub fn https_port() -> u16 {
    *HTTPS_PORT.get().unwrap_or(&47396)
}

pub fn eo_url(name: &str) -> String {
    let port = https_port();
    if port == 443 {
        format!("https://{}.eo", name)
    } else {
        format!("https://{}.eo:{}", name, port)
    }
}

pub fn certs_exist() -> bool {
    let dir = tls_dir();
    dir.join("wildcard.crt").exists() && dir.join("wildcard.key").exists()
}

pub fn get_tls_pem() -> Option<(String, String)> {
    let dir = tls_dir();
    let cert = std::fs::read_to_string(dir.join("wildcard.crt")).ok()?;
    let key  = std::fs::read_to_string(dir.join("wildcard.key")).ok()?;
    Some((cert, key))
}

pub fn ca_der_path() -> PathBuf {
    tls_dir().join("ca.der")
}

pub fn ensure_tls_certs() -> Result<(), String> {
    if certs_exist() {
        return Ok(());
    }
    let dir = tls_dir();

    let mut ca_params = CertificateParams::new(vec![]);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.distinguished_name.push(DnType::CommonName, "Ego Desktop Local CA");
    ca_params.distinguished_name.push(DnType::OrganizationName, "Ego Blockchain");
    ca_params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    ca_params.not_after  = rcgen::date_time_ymd(2035, 1, 1);

    let ca = Certificate::from_params(ca_params)
        .map_err(|e| format!("CA generation failed: {}", e))?;

    let ca_cert_pem = ca.serialize_pem()
        .map_err(|e| format!("CA PEM failed: {}", e))?;
    let ca_key_pem  = ca.serialize_private_key_pem();
    let ca_cert_der = ca.serialize_der()
        .map_err(|e| format!("CA DER failed: {}", e))?;

    std::fs::write(dir.join("ca.crt"), &ca_cert_pem).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("ca.key"), &ca_key_pem).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("ca.der"), &ca_cert_der).map_err(|e| e.to_string())?;

    let mut wc_params = CertificateParams::new(vec!["*.eo".to_string(), "eo".to_string()]);
    wc_params.is_ca = IsCa::NoCa;
    wc_params.distinguished_name = DistinguishedName::new();
    wc_params.distinguished_name.push(DnType::CommonName, "*.eo");
    wc_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    wc_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    wc_params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    wc_params.not_after  = rcgen::date_time_ymd(2035, 1, 1);

    let wc = Certificate::from_params(wc_params)
        .map_err(|e| format!("Wildcard cert failed: {}", e))?;
    let wc_cert_pem = wc.serialize_pem_with_signer(&ca)
        .map_err(|e| format!("Wildcard sign failed: {}", e))?;
    let wc_key_pem  = wc.serialize_private_key_pem();

    std::fs::write(dir.join("wildcard.crt"), &wc_cert_pem).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("wildcard.key"), &wc_key_pem).map_err(|e| e.to_string())?;

    eprintln!("[TLS] Certificates generated");
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn install_ca_to_store() -> Result<(), String> {
    let ca_path = ca_der_path();
    if !ca_path.exists() {
        return Err("CA certificate not found — run setup first".into());
    }
    let ca_path_str = ca_path.to_string_lossy();
    let script = format!(
        "certutil -addstore -f Root '{}'",
        ca_path_str.replace('\'', "\\'")
    );
    let ps_cmd = format!(
        "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile -NonInteractive -Command \"{}\"'",
        script.replace('"', "`\"")
    );
    std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_cmd])
        .status()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn install_ca_to_store() -> Result<(), String> {
    Err("Automatic CA installation is only supported on Windows".into())
}

#[cfg(target_os = "windows")]
pub fn add_eo_hosts_entry(name: &str) {
    let hosts = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    let existing = std::fs::read_to_string(hosts).unwrap_or_default();
    let entry = format!("{}.eo", name);
    if existing.contains(&entry) {
        return;
    }
    let lines = format!("127.0.0.1 {}.eo\r\n127.0.0.1 www.{}.eo\r\n", name, name);
    let tmp = std::env::temp_dir().join(format!("ego_hosts_{}.txt", name));
    if std::fs::write(&tmp, &lines).is_err() { return; }
    let tmp_str = tmp.to_string_lossy();
    let script = format!(
        "Get-Content -Path '{}' | Add-Content -Path '{}' -Encoding ASCII",
        tmp_str.replace('\'', "\\'"),
        hosts,
    );
    let ps_cmd = format!(
        "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile -NonInteractive -Command \"{}\"'",
        script.replace('"', "`\"")
    );
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_cmd])
        .output();
    let _ = std::fs::remove_file(&tmp);
}

#[cfg(not(target_os = "windows"))]
pub fn add_eo_hosts_entry(_name: &str) {}

pub fn hosts_has_entry(name: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        let hosts = std::fs::read_to_string("C:\\Windows\\System32\\drivers\\etc\\hosts")
            .unwrap_or_default();
        hosts.contains(&format!("{}.eo", name))
    }
    #[cfg(not(target_os = "windows"))]
    { let _ = name; false }
}

pub fn remove_eo_hosts_entry(name: &str) {
    #[cfg(target_os = "windows")]
    {
        let hosts_path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
        if let Ok(content) = std::fs::read_to_string(hosts_path) {
            let filtered: String = content
                .lines()
                .filter(|l| !l.contains(&format!("{}.eo", name)))
                .map(|l| format!("{}\r\n", l))
                .collect();
            let tmp = std::env::temp_dir().join(format!("ego_hosts_rm_{}.txt", name));
            if std::fs::write(&tmp, &filtered).is_ok() {
                let tmp_str = tmp.to_string_lossy();
                let script = format!(
                    "Copy-Item -Path '{}' -Destination '{}' -Force",
                    tmp_str.replace('\'', "\\'"),
                    hosts_path,
                );
                let ps_cmd = format!(
                    "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile -NonInteractive -Command \"{}\"'",
                    script.replace('"', "`\"")
                );
                let _ = std::process::Command::new("powershell")
                    .args(["-NoProfile", "-Command", &ps_cmd])
                    .output();
                let _ = std::fs::remove_file(&tmp);
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    { let _ = name; }
}
