import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type AppInfo = {
  name: string;
  version: string;
  phase: string;
  platform: string;
  localOnly: boolean;
};

type Peer = {
  id: string;
  name: string;
  status: "available" | "offline";
  detail: string;
  initials: string;
  accent: string;
};

const demoPeers: Peer[] = [
  {
    id: "studio-pc",
    name: "Studio PC",
    status: "available",
    detail: "Ready to receive",
    initials: "SP",
    accent: "violet",
  },
  {
    id: "design-laptop",
    name: "Design Laptop",
    status: "available",
    detail: "Ready to receive",
    initials: "DL",
    accent: "cyan",
  },
  {
    id: "archive-pc",
    name: "Archive PC",
    status: "offline",
    detail: "Last seen 18 min ago",
    initials: "AP",
    accent: "amber",
  },
];

const files = [
  { name: "Project files", type: "folder", meta: "12 items", icon: "folder" },
  { name: "Product brief.pdf", type: "PDF", meta: "2.4 MB", icon: "pdf" },
  { name: "Launch assets", type: "folder", meta: "48 items", icon: "folder" },
  { name: "Roadmap.xlsx", type: "XLSX", meta: "840 KB", icon: "sheet" },
];

const fallbackInfo: AppInfo = {
  name: "Zapdrop",
  version: "0.1.0",
  phase: "Desktop scaffold",
  platform: "browser preview",
  localOnly: true,
};

function App() {
  const [appInfo, setAppInfo] = useState<AppInfo>(fallbackInfo);
  const [selectedPeers, setSelectedPeers] = useState<string[]>(["studio-pc"]);
  const [selectedFile, setSelectedFile] = useState("Project files");
  const [notice, setNotice] = useState("Select a file and a nearby PC to prepare a share.");
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    let active = true;
    invoke<AppInfo>("get_app_info")
      .then((info) => {
        if (active) setAppInfo(info);
      })
      .catch(() => {
        // Vite browser preview intentionally uses a local fallback until Tauri is running.
      });
    return () => {
      active = false;
    };
  }, []);

  const availablePeerCount = useMemo(
    () => demoPeers.filter((peer) => peer.status === "available").length,
    [],
  );

  function togglePeer(peer: Peer) {
    if (peer.status === "offline") return;
    setSelectedPeers((current) =>
      current.includes(peer.id)
        ? current.filter((id) => id !== peer.id)
        : [...current, peer.id],
    );
    setNotice(`${peer.name} ${selectedPeers.includes(peer.id) ? "removed from" : "added to"} the share.`);
  }

  function handleScan() {
    setScanning(true);
    setNotice("Scanning the local network will be connected in Phase 3.");
    window.setTimeout(() => setScanning(false), 900);
  }

  function handleShare() {
    if (!selectedPeers.length) {
      setNotice("Choose at least one available PC before sharing.");
      return;
    }
    setNotice(`Share prepared: ${selectedFile} → ${selectedPeers.length} PC${selectedPeers.length > 1 ? "s" : ""}.`);
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true"><span /></div>
          <div>
            <div className="brand-name">zapdrop</div>
            <div className="brand-caption">Local file movement</div>
          </div>
        </div>

        <nav className="primary-nav" aria-label="Primary navigation">
          <button className="nav-item active"><Icon name="grid" /> Overview</button>
          <button className="nav-item"><Icon name="arrow-up" /> Sent</button>
          <button className="nav-item"><Icon name="arrow-down" /> Received</button>
          <button className="nav-item"><Icon name="clock" /> History</button>
        </nav>

        <div className="sidebar-divider" />
        <div className="sidebar-section-label">Workspace</div>
        <button className="workspace-card">
          <span className="workspace-icon"><Icon name="desktop" /></span>
          <span>
            <strong>This PC</strong>
            <small>Local files</small>
          </span>
          <Icon name="chevron" />
        </button>

        <div className="sidebar-footer">
          <div className="privacy-note">
            <span className="status-dot green" />
            <div><strong>Private by design</strong><small>No cloud required</small></div>
          </div>
          <button className="nav-item muted"><Icon name="settings" /> Settings</button>
          <div className="profile-row"><div className="profile-avatar">JD</div><div><strong>Jordan Davis</strong><small>Personal workspace</small></div><Icon name="more" /></div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <div className="eyebrow">Local workspace <span className="slash">/</span> Overview</div>
            <h1>Good morning, Jordan <span className="wave">✦</span></h1>
          </div>
          <div className="topbar-actions">
            <div className="connection-pill"><span className="status-dot green" /> Local network <strong>Online</strong></div>
            <button className="icon-button" aria-label="Notifications"><Icon name="bell" /><span className="notification-dot" /></button>
            <button className="avatar-button">JD</button>
          </div>
        </header>

        <section className="hero-card">
          <div className="hero-copy">
            <div className="hero-kicker"><span className="sparkle">✦</span> Phase 1 is ready</div>
            <h2>Move files<br /><span>without the cloud.</span></h2>
            <p>Zapdrop keeps your files on the local network, moving them directly between trusted PCs.</p>
            <div className="hero-actions"><button className="button primary" onClick={handleScan}><Icon name="radar" /> {scanning ? "Scanning..." : "Scan for PCs"}</button><button className="button ghost"><Icon name="info" /> How it works</button></div>
          </div>
          <div className="hero-visual" aria-hidden="true">
            <div className="orbit orbit-one" /><div className="orbit orbit-two" />
            <div className="visual-node node-center"><div className="node-icon"><Icon name="zap" /></div><span>This PC</span></div>
            <div className="visual-node node-top"><div className="node-icon"><Icon name="desktop" /></div><span>Studio PC</span></div>
            <div className="visual-node node-right"><div className="node-icon"><Icon name="laptop" /></div><span>Design Laptop</span></div>
            <div className="packet packet-one">↗</div><div className="packet packet-two">↙</div>
          </div>
        </section>

        <div className="section-heading"><div><div className="section-kicker">Nearby devices <span className="count-badge">{availablePeerCount}</span></div><h3>Ready to connect</h3></div><button className="text-button" onClick={handleScan}>View all <Icon name="arrow-right" /></button></div>
        <section className="peer-grid">
          {demoPeers.map((peer) => {
            const selected = selectedPeers.includes(peer.id);
            return <button key={peer.id} className={`peer-card ${selected ? "selected" : ""} ${peer.status === "offline" ? "offline" : ""}`} onClick={() => togglePeer(peer)}>
              <div className={`peer-avatar ${peer.accent}`}>{peer.initials}{selected && <span className="check-badge"><Icon name="check" /></span>}</div>
              <div className="peer-copy"><strong>{peer.name}</strong><span><i className={`status-dot ${peer.status === "available" ? "green" : "gray"}`} /> {peer.detail}</span></div>
              <Icon name="more" />
            </button>;
          })}
          <button className="peer-card add-peer"><span className="add-icon">+</span><div className="peer-copy"><strong>Add a PC</strong><span>Connect manually</span></div><Icon name="arrow-right" /></button>
        </section>

        <div className="content-columns">
          <section className="panel explorer-panel">
            <div className="panel-header"><div><div className="section-kicker">Your files</div><h3>Choose something to share</h3></div><button className="view-toggle"><Icon name="list" /><Icon name="layout" /></button></div>
            <div className="path-bar"><Icon name="folder" /><span>Home</span><Icon name="chevron" /><strong>Jordan Davis</strong><span className="path-spacer" /><button><Icon name="search" /></button></div>
            <div className="file-list">
              {files.map((file) => <button key={file.name} className={`file-row ${selectedFile === file.name ? "selected" : ""}`} onClick={() => { setSelectedFile(file.name); setNotice(`${file.name} selected.`); }}><span className={`file-icon ${file.icon}`}><Icon name={file.icon} /></span><span className="file-name"><strong>{file.name}</strong><small>{file.type}</small></span><span className="file-meta">{file.meta}</span><Icon name="more" /></button>)}
            </div>
            <button className="browse-button"><Icon name="folder-plus" /> Browse local files</button>
          </section>

          <section className="panel share-panel">
            <div className="panel-header"><div><div className="section-kicker">Quick share</div><h3>Send selected items</h3></div><span className="mini-status"><span className="status-dot green" /> Secure</span></div>
            <div className="share-preview"><span className="file-icon folder"><Icon name="folder" /></span><div><strong>{selectedFile}</strong><span>Selected from this PC</span></div><Icon name="check-circle" /></div>
            <div className="recipient-label">Recipients <span>{selectedPeers.length} selected</span></div>
            <div className="recipient-stack">{demoPeers.filter((peer) => peer.status === "available").map((peer) => <button key={peer.id} className={`recipient-chip ${selectedPeers.includes(peer.id) ? "selected" : ""}`} onClick={() => togglePeer(peer)}><span className={`mini-avatar ${peer.accent}`}>{peer.initials}</span>{peer.name}<span className="chip-check">{selectedPeers.includes(peer.id) ? <Icon name="check" /> : "+"}</span></button>)}</div>
            <div className="share-note"><Icon name="lock" /><span>Files move directly over your local network.<br /><strong>Internet is never required.</strong></span></div>
            <button className="button primary full" onClick={handleShare}>Share now <Icon name="arrow-right" /></button>
            <div className="notice" role="status"><span className="notice-mark">i</span>{notice}</div>
          </section>
        </div>

        <section className="bridge-status"><span className="bridge-icon"><Icon name="code" /></span><div><strong>Native bridge connected</strong><span>{appInfo.name} {appInfo.version} · {appInfo.phase} · {appInfo.platform}</span></div><span className="bridge-check"><Icon name="check" /></span></section>
      </main>
    </div>
  );
}

function Icon({ name }: { name: string }) {
  const paths: Record<string, string> = {
    grid: "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z",
    "arrow-up": "M12 19V5m0 0-5 5m5-5 5 5",
    "arrow-down": "M12 5v14m0 0 5-5m-5 5-5-5",
    clock: "M12 7v5l3 2m6-2a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
    desktop: "M4 5h16v10H4zM8 19h8m-4-4v4",
    laptop: "M4 6h16v10H4zM2 19h20",
    settings: "M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Zm0-12v2m0 13v2m8.5-8.5h-2m-13 0h-2m14.1-6.1-1.4 1.4M7.8 16.2l-1.4 1.4m11.2 0-1.4-1.4M7.8 7.8 6.4 6.4",
    more: "M6 12h.01M12 12h.01M18 12h.01",
    chevron: "m9 18 6-6-6-6",
    bell: "M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9m-8 13h4",
    radar: "M4 12a8 8 0 0 1 14.7-4.4M20 12a8 8 0 0 1-14.7 4.4M12 12h.01",
    info: "M12 16v-4m0-4h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
    zap: "m13 2-9 12h7l-1 8 9-12h-7l1-8Z",
    "arrow-right": "M5 12h14m-6-6 6 6-6 6",
    folder: "M3 6h6l2 2h10v10H3z",
    pdf: "M6 3h8l4 4v14H6zM14 3v5h5",
    sheet: "M6 3h12v18H6zm3 5h6m-6 4h6m-6 4h4",
    list: "M5 6h.01M9 6h10M5 12h.01M9 12h10M5 18h.01M9 18h10",
    layout: "M4 4h6v16H4zM14 4h6v7h-6zM14 14h6v6h-6z",
    search: "m20 20-4.3-4.3m1.3-5.2a6.5 6.5 0 1 1-13 0 6.5 6.5 0 0 1 13 0Z",
    "folder-plus": "M3 6h6l2 2h10v10H3zm9 5v6m-3-3h6",
    "check-circle": "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-13-1 3 3 5-6",
    lock: "M6 10V8a6 6 0 0 1 12 0v2m-14 0h16v10H4z",
    check: "m5 12 4 4L19 6",
    code: "m8 9-3 3 3 3m8-6 3 3-3 3m-3-8-2 10",
  };
  return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name] ?? paths.info} /></svg>;
}

export default App;
