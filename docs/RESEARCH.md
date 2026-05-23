# Research Notes

Production-grade Linux endpoint visibility should be built around kernel-native event sources where possible:

- `auditd` or eBPF for process exec, privilege changes, auth-related activity, and high-fidelity command metadata.
- fanotify permission events for file access decisions that need pre-read/pre-copy DLP control.
- udev plus USBGuard for removable media inventory and per-device policy.
- netlink/conntrack/eBPF and DNS logs for browser/internet visibility.
- Managed browser extension or proxy integration for full URL, upload, download, webmail, and SaaS channel context.

The current agent keeps dependencies small and works in containers and developer machines, but it is a baseline. The production path is to replace polling collectors with these event sources behind the same wire model.
