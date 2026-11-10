# Security policy

Sentinel Desk is a single-user, loopback-only educational application. It has no authentication and must not be exposed through a tunnel, proxy or public interface.

The intended inputs are small log exports from a trusted operator. HTTP input is limited to 2 MiB per request; total database growth and CLI input are not bounded. Use a disposable database for untrusted samples.

Do not submit real incident logs, credentials, IP inventories or personal information in public issues. For a security report, share a minimal synthetic reproducer and the affected version. If the repository has private vulnerability reporting enabled, use that feature; this repository does not guarantee a private reporting channel or response SLA.
