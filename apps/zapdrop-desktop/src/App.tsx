import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

type AppInfo = {
  name: string;
  version: string;
  phase: string;
  platform: string;
  localOnly: boolean;
  deviceId: string;
  deviceName: string;
  fingerprint: string;
  keyStorage: string;
  dataDirectory: string;
};

type Peer = {
  id: string;
  name: string;
  platform: string;
  fingerprint?: string | null;
  endpoint: string;
  port: number;
  status: string;
  discoveredVia: string;
  lastSeen: number;
  trusted: boolean;
};

type AppSettings = {
  version: number;
  deviceName: string;
  receiveDirectory: string;
  selectedInterface: string | null;
  advertiseOnStartup: boolean;
};

type NetworkDiagnostics = {
  localIp: string;
  listeningPort: number;
  serviceType: string;
  mdnsAvailable: boolean;
  manualFallbackAvailable: boolean;
  interfaceNote: string;
};

const demoPeers: Peer[] = [
  { id: "studio-pc", name: "Studio PC", platform: "windows", endpoint: "192.168.1.20:53317", port: 53317, status: "online", discoveredVia: "preview", lastSeen: 0, trusted: false },
  { id: "design-laptop", name: "Design Laptop", platform: "windows", endpoint: "192.168.1.21:53317", port: 53317, status: "online", discoveredVia: "preview", lastSeen: 0, trusted: false },
  { id: "archive-pc", name: "Archive PC", platform: "windows", endpoint: "offline", port: 0, status: "offline", discoveredVia: "preview", lastSeen: 0, trusted: false },
];

const files = [
  { name: "Project files", type: "folder", meta: "12 items", icon: "folder" },
  { name: "Product brief.pdf", type: "PDF", meta: "2.4 MB", icon: "pdf" },
  { name: "Launch assets", type: "folder", meta: "48 items", icon: "folder" },
  { name: "Roadmap.xlsx", type: "XLSX", meta: "840 KB", icon: "sheet" },
];

const fallbackInfo: AppInfo = {
  name: "Zapdrop", version: "0.1.0", phase: "browser preview", platform: "browser", localOnly: true,
  deviceId: "preview-device", deviceName: "This PC", fingerprint: "preview only", keyStorage: "preview", dataDirectory: "browser preview",
};
const fallbackSettings: AppSettings = { version: 1, deviceName: "This PC", receiveDirectory: "~/Downloads/Zapdrop", selectedInterface: null, advertiseOnStartup: true };
const fallbackDiagnostics: NetworkDiagnostics = { localIp: "Preview only", listeningPort: 0, serviceType: "_zapdrop._tcp.local.", mdnsAvailable: false, manualFallbackAvailable: true, interfaceNote: "Run the Tauri desktop app to inspect the local network." };

function App() {
  const [appInfo, setAppInfo] = useState<AppInfo>(fallbackInfo);
  const [settings, setSettings] = useState<AppSettings>(fallbackSettings);
  const [diagnostics, setDiagnostics] = useState<NetworkDiagnostics>(fallbackDiagnostics);
  const [peers, setPeers] = useState<Peer[]>([]);
  const [selectedPeers, setSelectedPeers] = useState<string[]>([]);
  const [selectedFile, setSelectedFile] = useState("Project files");
  const [notice, setNotice] = useState("Select a file and a nearby PC to prepare a share.");
  const [scanning, setScanning] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [manualEndpoint, setManualEndpoint] = useState("");
  const [settingsDraft, setSettingsDraft] = useState<AppSettings>(fallbackSettings);

  const visiblePeers = peers.length ? peers : demoPeers;
  const availablePeers = visiblePeers.filter((peer) => peer.status === "online" || peer.status === "available" || peer.status === "manual");
  const availablePeerCount = availablePeers.length;
  const networkLabel = diagnostics.mdnsAvailable ? "mDNS active" : "Manual fallback";

  useEffect(() => {
    let active = true;
    Promise.all([
      invoke<AppInfo>("get_app_info"),
      invoke<AppSettings>("get_settings"),
      invoke<NetworkDiagnostics>("get_network_diagnostics"),
      invoke<Peer[]>("list_peers"),
    ]).then(([info, loadedSettings, loadedDiagnostics, loadedPeers]) => {
      if (!active) return;
      setAppInfo(info);
      setSettings(loadedSettings);
      setSettingsDraft(loadedSettings);
      setDiagnostics(loadedDiagnostics);
      setPeers(loadedPeers);
    }).catch(() => {
      // Browser preview intentionally keeps its local fallback data.
    });

    let unlisteners: UnlistenFn[] = [];
    Promise.all([
      listen<Peer>("peer-updated", (event) => setPeers((current) => upsertPeer(current, event.payload))),
      listen<Peer>("peer-removed", (event) => setPeers((current) => current.filter((peer) => peer.id !== event.payload.id))),
      listen<Peer[]>("scan-complete", (event) => setPeers(event.payload)),
      listen<AppSettings>("settings-updated", (event) => { setSettings(event.payload); setSettingsDraft(event.payload); }),
    ]).then((handlers) => { if (active) unlisteners = handlers; else handlers.forEach((unlisten) => unlisten()); }).catch(() => {});
    return () => { active = false; unlisteners.forEach((unlisten) => unlisten()); };
  }, []);

  function togglePeer(peer: Peer) {
    if (peer.status === "offline") return;
    setSelectedPeers((current) => current.includes(peer.id) ? current.filter((id) => id !== peer.id) : [...current, peer.id]);
    setNotice(`${peer.name} ${selectedPeers.includes(peer.id) ? "removed from" : "added to"} the share.`);
  }

  async function handleScan() {
    setScanning(true);
    setNotice("Scanning the local network...");
    try {
      const found = await invoke<Peer[]>("scan_network");
      setPeers(found);
      setNotice(found.length ? `Found ${found.length} Zapdrop peer${found.length === 1 ? "" : "s"}.` : "No peers found. Try the manual endpoint fallback.");
    } catch {
      setNotice("Discovery is available in the Tauri desktop runtime; browser preview uses sample peers.");
    } finally {
      window.setTimeout(() => setScanning(false), 500);
    }
  }

  async function saveSettings() {
    try {
      const saved = await invoke<AppSettings>("update_settings", { patch: { deviceName: settingsDraft.deviceName, receiveDirectory: settingsDraft.receiveDirectory, selectedInterface: settingsDraft.selectedInterface, advertiseOnStartup: settingsDraft.advertiseOnStartup } });
      setSettings(saved); setSettingsDraft(saved); setSettingsOpen(false); setNotice("Settings saved. Discovery was restarted if needed.");
      const refreshed = await invoke<AppInfo>("get_app_info"); setAppInfo(refreshed);
    } catch {
      setSettings(settingsDraft); setSettingsOpen(false); setNotice("Settings preview saved locally; run the Tauri app to persist them.");
    }
  }

  async function resetIdentity() {
    if (!window.confirm("Reset this device identity? Existing trusted peers will need to pair again.")) return;
    try {
      const refreshed = await invoke<AppInfo>("reset_identity"); setAppInfo(refreshed); setNotice("Device identity reset. Trusted peer bindings must be recreated.");
    } catch { setNotice("Identity reset is available in the Tauri desktop runtime."); }
  }

  async function addManualPeer() {
    if (!manualEndpoint.trim()) return;
    try {
      const peer = await invoke<Peer>("add_manual_endpoint", { endpoint: manualEndpoint.trim() });
      setPeers((current) => upsertPeer(current, peer)); setSelectedPeers((current) => [...new Set([...current, peer.id])]); setManualEndpoint(""); setNotice(`Manual endpoint added: ${peer.endpoint}. Pairing is still required.`);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Enter a private IP address and port, such as 192.168.1.20:53317."); }
  }

  function handleShare() {
    if (!selectedPeers.length) { setNotice("Choose at least one available PC before sharing."); return; }
    setNotice(`Share prepared: ${selectedFile} → ${selectedPeers.length} PC${selectedPeers.length > 1 ? "s" : ""}. Transfer arrives in a later phase.`);
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand-lockup"><div className="brand-mark" aria-hidden="true"><span /></div><div><div className="brand-name">zapdrop</div><div className="brand-caption">Local file movement</div></div></div>
      <nav className="primary-nav" aria-label="Primary navigation"><button className="nav-item active"><Icon name="grid" /> Overview</button><button className="nav-item"><Icon name="arrow-up" /> Sent</button><button className="nav-item"><Icon name="arrow-down" /> Received</button><button className="nav-item"><Icon name="clock" /> History</button></nav>
      <div className="sidebar-divider" /><div className="sidebar-section-label">Workspace</div><button className="workspace-card"><span className="workspace-icon"><Icon name="desktop" /></span><span><strong>{appInfo.deviceName}</strong><small>Local files</small></span><Icon name="chevron" /></button>
      <div className="sidebar-footer"><div className="privacy-note"><span className="status-dot green" /><div><strong>Private by design</strong><small>No cloud required</small></div></div><button className="nav-item muted" onClick={() => setSettingsOpen(true)}><Icon name="settings" /> Settings</button><div className="profile-row"><div className="profile-avatar">{initials(appInfo.deviceName)}</div><div><strong>{appInfo.deviceName}</strong><small>{appInfo.platform}</small></div><Icon name="more" /></div></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><div><div className="eyebrow">Local workspace <span className="slash">/</span> Overview</div><h1>Good morning, {appInfo.deviceName} <span className="wave">✦</span></h1></div><div className="topbar-actions"><div className="connection-pill"><span className={`status-dot ${diagnostics.mdnsAvailable ? "green" : "gray"}`} /> {networkLabel} <strong>{diagnostics.localIp}</strong></div><button className="icon-button" aria-label="Notifications"><Icon name="bell" /><span className="notification-dot" /></button><button className="avatar-button">{initials(appInfo.deviceName)}</button></div></header>
      <section className="hero-card"><div className="hero-copy"><div className="hero-kicker"><span className="sparkle">✦</span> Phase 2 is connected</div><h2>Move files<br /><span>without the cloud.</span></h2><p>Zapdrop keeps your files on the local network, moving them directly between trusted PCs.</p><div className="hero-actions"><button className="button primary" onClick={handleScan}><Icon name="radar" /> {scanning ? "Scanning..." : "Scan for PCs"}</button><button className="button ghost" onClick={() => setSettingsOpen(true)}><Icon name="settings" /> Device settings</button></div></div><div className="hero-visual" aria-hidden="true"><div className="orbit orbit-one" /><div className="orbit orbit-two" /><div className="visual-node node-center"><div className="node-icon"><Icon name="zap" /></div><span>{appInfo.deviceName}</span></div><div className="visual-node node-top"><div className="node-icon"><Icon name="desktop" /></div><span>{availablePeers[0]?.name ?? "Nearby PC"}</span></div><div className="visual-node node-right"><div className="node-icon"><Icon name="laptop" /></div><span>{availablePeers[1]?.name ?? "Waiting"}</span></div><div className="packet packet-one">↗</div><div className="packet packet-two">↙</div></div></section>
      <div className="section-heading"><div><div className="section-kicker">Nearby devices <span className="count-badge">{availablePeerCount}</span></div><h3>Ready to connect</h3></div><button className="text-button" onClick={handleScan}>Refresh <Icon name="arrow-right" /></button></div>
      <section className="peer-grid">{visiblePeers.map((peer) => { const selected = selectedPeers.includes(peer.id); return <button key={peer.id} className={`peer-card ${selected ? "selected" : ""} ${peer.status === "offline" ? "offline" : ""}`} onClick={() => togglePeer(peer)}><div className={`peer-avatar ${accent(peer.name)}`}>{initials(peer.name)}{selected && <span className="check-badge"><Icon name="check" /></span>}</div><div className="peer-copy"><strong>{peer.name}</strong><span><i className={`status-dot ${peer.status === "offline" ? "gray" : "green"}`} /> {peer.status === "manual" ? "Manual endpoint" : peer.status === "offline" ? "Offline" : peer.discoveredVia === "mdns" ? "Discovered by mDNS" : "Preview peer"}</span></div><Icon name="more" /></button>; })}<button className="peer-card add-peer" onClick={() => setSettingsOpen(true)}><span className="add-icon">+</span><div className="peer-copy"><strong>Add a PC</strong><span>Connect manually</span></div><Icon name="arrow-right" /></button></section>
      <div className="content-columns"><section className="panel explorer-panel"><div className="panel-header"><div><div className="section-kicker">Your files</div><h3>Choose something to share</h3></div><button className="view-toggle"><Icon name="list" /><Icon name="layout" /></button></div><div className="path-bar"><Icon name="folder" /><span>Home</span><Icon name="chevron" /><strong>{appInfo.deviceName}</strong><span className="path-spacer" /><button><Icon name="search" /></button></div><div className="file-list">{files.map((file) => <button key={file.name} className={`file-row ${selectedFile === file.name ? "selected" : ""}`} onClick={() => { setSelectedFile(file.name); setNotice(`${file.name} selected.`); }}><span className={`file-icon ${file.icon}`}><Icon name={file.icon} /></span><span className="file-name"><strong>{file.name}</strong><small>{file.type}</small></span><span className="file-meta">{file.meta}</span><Icon name="more" /></button>)}</div><button className="browse-button"><Icon name="folder-plus" /> Browse local files <span className="phase-tag">Phase 5</span></button></section>
      <section className="panel share-panel"><div className="panel-header"><div><div className="section-kicker">Quick share</div><h3>Send selected items</h3></div><span className="mini-status"><span className="status-dot green" /> Secure</span></div><div className="share-preview"><span className="file-icon folder"><Icon name="folder" /></span><div><strong>{selectedFile}</strong><span>Selected from this PC</span></div><Icon name="check-circle" /></div><div className="recipient-label">Recipients <span>{selectedPeers.length} selected</span></div><div className="recipient-stack">{availablePeers.map((peer) => <button key={peer.id} className={`recipient-chip ${selectedPeers.includes(peer.id) ? "selected" : ""}`} onClick={() => togglePeer(peer)}><span className={`mini-avatar ${accent(peer.name)}`}>{initials(peer.name)}</span>{peer.name}<span className="chip-check">{selectedPeers.includes(peer.id) ? <Icon name="check" /> : "+"}</span></button>)}</div><div className="share-note"><Icon name="lock" /><span>Files move directly over your local network.<br /><strong>Internet is never required.</strong></span></div><button className="button primary full" onClick={handleShare}>Share now <Icon name="arrow-right" /></button><div className="notice" role="status"><span className="notice-mark">i</span>{notice}</div></section></div>
      <section className="diagnostics-strip"><div><span className="diagnostics-title"><Icon name="radar" /> Network discovery</span><span>{diagnostics.serviceType} · {diagnostics.localIp}:{diagnostics.listeningPort || "not listening"}</span></div><div className="diagnostic-actions"><span className={`diagnostic-state ${diagnostics.mdnsAvailable ? "ok" : "fallback"}`}>{diagnostics.mdnsAvailable ? "mDNS available" : "Manual fallback available"}</span><button className="small-button" onClick={() => setSettingsOpen(true)}>Configure</button></div></section>
      <section className="bridge-status"><span className="bridge-icon"><Icon name="code" /></span><div><strong>Native bridge connected</strong><span>{appInfo.name} {appInfo.version} · {appInfo.phase} · {appInfo.keyStorage}</span></div><span className="bridge-check"><Icon name="check" /></span></section>
    </main>
    {settingsOpen && <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setSettingsOpen(false); }}><section className="settings-modal" role="dialog" aria-modal="true" aria-labelledby="settings-title"><div className="modal-header"><div><div className="section-kicker">Phase 2 controls</div><h2 id="settings-title">Device settings</h2></div><button className="modal-close" onClick={() => setSettingsOpen(false)}>×</button></div><label>Device name<input value={settingsDraft.deviceName} onChange={(event) => setSettingsDraft({ ...settingsDraft, deviceName: event.target.value })} maxLength={64} /></label><label>Receive directory<input value={settingsDraft.receiveDirectory} onChange={(event) => setSettingsDraft({ ...settingsDraft, receiveDirectory: event.target.value })} /></label><label>Manual local endpoint<input value={manualEndpoint} onChange={(event) => setManualEndpoint(event.target.value)} placeholder="192.168.1.20:53317" /></label><div className="modal-inline"><button className="small-button" onClick={addManualPeer}>Add endpoint</button><span>Private/local IP addresses only</span></div><label className="toggle-row"><input type="checkbox" checked={settingsDraft.advertiseOnStartup} onChange={(event) => setSettingsDraft({ ...settingsDraft, advertiseOnStartup: event.target.checked })} /><span>Advertise and browse on startup</span></label><div className="identity-card"><span className="file-icon folder"><Icon name="lock" /></span><div><strong>Device identity</strong><span>{appInfo.fingerprint}</span><small>{appInfo.deviceId} · {appInfo.keyStorage}</small></div></div><div className="modal-actions"><button className="button ghost" onClick={resetIdentity}>Reset identity</button><button className="button primary" onClick={saveSettings}>Save settings</button></div></section></div>}
  </div>;
}

function upsertPeer(current: Peer[], peer: Peer) { return [...current.filter((item) => item.id !== peer.id), peer]; }
function initials(value: string) { return value.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]?.toUpperCase()).join("") || "PC"; }
function accent(value: string) { return ["violet", "cyan", "amber"][Math.abs([...value].reduce((sum, char) => sum + char.charCodeAt(0), 0)) % 3]; }

function Icon({ name }: { name: string }) {
  const paths: Record<string, string> = { grid: "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z", "arrow-up": "M12 19V5m0 0-5 5m5-5 5 5", "arrow-down": "M12 5v14m0 0 5-5m-5 5-5-5", clock: "M12 7v5l3 2m6-2a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z", desktop: "M4 5h16v10H4zM8 19h8m-4-4v4", laptop: "M4 6h16v10H4zM2 19h20", settings: "M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Zm0-12v2m0 13v2m8.5-8.5h-2m-13 0h-2m14.1-6.1-1.4 1.4M7.8 16.2l-1.4 1.4m11.2 0-1.4-1.4M7.8 7.8 6.4 6.4", more: "M6 12h.01M12 12h.01M18 12h.01", chevron: "m9 18 6-6-6-6", bell: "M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9m-8 13h4", radar: "M4 12a8 8 0 0 1 14.7-4.4M20 12a8 8 0 0 1-14.7 4.4M12 12h.01", info: "M12 16v-4m0-4h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z", zap: "m13 2-9 12h7l-1 8 9-12h-7l1-8Z", "arrow-right": "M5 12h14m-6-6 6 6-6 6", folder: "M3 6h6l2 2h10v10H3z", pdf: "M6 3h8l4 4v14H6zM14 3v5h5", sheet: "M6 3h12v18H6zm3 5h6m-6 4h6m-6 4h4", list: "M5 6h.01M9 6h10M5 12h.01M9 12h10M5 18h.01M9 18h10", layout: "M4 4h6v16H4zM14 4h6v7h-6zM14 14h6v6h-6z", search: "m20 20-4.3-4.3m1.3-5.2a6.5 6.5 0 1 1-13 0 6.5 6.5 0 0 1 13 0Z", "folder-plus": "M3 6h6l2 2h10v10H3zm9 5v6m-3-3h6", "check-circle": "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-13-1 3 3 5-6", lock: "M6 10V8a6 6 0 0 1 12 0v2m-14 0h16v10H4z", check: "m5 12 4 4L19 6", code: "m8 9-3 3 3 3m8-6 3 3-3 3m-3-8-2 10" };
  return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name] ?? paths.info} /></svg>;
}

export default App;
