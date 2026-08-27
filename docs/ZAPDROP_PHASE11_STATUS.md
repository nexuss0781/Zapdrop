# Zapdrop Phase 11 Status

**Status:** Standalone companion contract implemented; full protocol runtime and platform qualification remain open.

A separate `apps/zapdrop-companion` Rust crate now builds without Tauri, WebView2, GTK, or desktop GUI dependencies. It reports its capabilities, negotiates the highest common Zapdrop protocol version, requires explicit receive approval in its advertised contract, and applies strict relative-path validation. This provides a clean build boundary for a future legacy-Windows or minimal-client companion.

The companion currently advertises v1 and v2 protocol identifiers but sets `secureV2Transport` to false. It is therefore a contract and packaging foundation, not a drop-in file-transfer implementation. Before release it must share the production handshake, trust persistence, v2 encrypted framing, snapshot, approval, journal, and history contracts with the Tauri client, then be built and tested on the actual supported Windows versions.

No compatibility claim is made for Windows 7/8.1 until a real user requirement, toolchain build, runtime smoke test, and security review justify that support. Modern Windows remains the primary supported client.
