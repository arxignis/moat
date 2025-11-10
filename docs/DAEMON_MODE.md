# Daemon Mode Implementation

This document describes the daemon mode implementation for Moat.

## Overview

Moat now supports running as a daemon (background process) using the [daemonize](https://docs.rs/daemonize/latest/daemonize/) crate. This allows Moat to run as a system service with proper privilege dropping and process management.

## Features

- **Background execution**: Runs as a detached background process
- **PID file management**: Creates and manages PID files for process control
- **Privilege dropping**: Can drop privileges to a specified user and group after initialization
- **Output redirection**: Redirects stdout and stderr to configurable log files
- **Working directory**: Configurable working directory for the daemon
- **Signal handling**: Proper signal handling for graceful shutdown

## Configuration

### Configuration File (YAML)

```yaml
daemon:
  enabled: false                        # Enable daemon mode
  pid_file: "/var/run/moat.pid"       # PID file path
  working_directory: "/"               # Working directory
  stdout: "/var/log/moat.out"         # Stdout log file
  stderr: "/var/log/moat.err"         # Stderr log file
  user: "nobody"                       # User to run as (optional)
  group: "daemon"                      # Group to run as (optional)
  chown_pid_file: true                # Change PID file ownership to user/group
```

### Command Line Arguments

- `--daemon`, `-d` - Run as daemon in background
- `--daemon-pid-file <PATH>` - PID file path (default: `/var/run/moat.pid`)
- `--daemon-working-dir <PATH>` - Working directory (default: `/`)
- `--daemon-stdout <PATH>` - Stdout log file (default: `/var/log/moat.out`)
- `--daemon-stderr <PATH>` - Stderr log file (default: `/var/log/moat.err`)
- `--daemon-user <USER>` - User to run as (e.g., `nobody`)
- `--daemon-group <GROUP>` - Group to run as (e.g., `daemon`)

### Environment Variables

- `AX_DAEMON_ENABLED` - Enable daemon mode (true/false)
- `AX_DAEMON_PID_FILE` - PID file path
- `AX_DAEMON_WORKING_DIRECTORY` - Working directory
- `AX_DAEMON_STDOUT` - Stdout log file
- `AX_DAEMON_STDERR` - Stderr log file
- `AX_DAEMON_USER` - User to run as
- `AX_DAEMON_GROUP` - Group to run as
- `AX_DAEMON_CHOWN_PID_FILE` - Change PID file ownership (true/false)

## Usage Examples

### Basic Daemon Mode

```bash
moat --daemon --iface eth0 --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key"
```

### Custom Daemon Settings

```bash
moat --daemon \
  --daemon-pid-file /var/run/moat.pid \
  --daemon-working-dir / \
  --daemon-stdout /var/log/moat.out \
  --daemon-stderr /var/log/moat.err \
  --daemon-user nobody \
  --daemon-group daemon \
  --iface eth0 --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key"
```

### With Configuration File

```bash
# config.yaml
daemon:
  enabled: true
  pid_file: "/var/run/moat.pid"
  working_directory: "/"
  stdout: "/var/log/moat.out"
  stderr: "/var/log/moat.err"
  user: "nobody"
  group: "daemon"
  chown_pid_file: true

# Run with config file
moat --config config.yaml
```

### With Environment Variables

```bash
export AX_DAEMON_ENABLED="true"
export AX_DAEMON_PID_FILE="/var/run/moat.pid"
export AX_DAEMON_USER="nobody"
export AX_DAEMON_GROUP="daemon"

moat --iface eth0 --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key"
```

## Process Management

### Starting the Daemon

```bash
moat --daemon --config /etc/moat/config.yaml
```

### Stopping the Daemon

```bash
# Using PID file
kill $(cat /var/run/moat.pid)

# Or send SIGTERM
kill -TERM $(cat /var/run/moat.pid)

# Graceful shutdown with SIGINT
kill -INT $(cat /var/run/moat.pid)
```

### Checking Status

```bash
# Check if process is running
ps aux | grep moat

# Or check PID file
if [ -f /var/run/moat.pid ]; then
    pid=$(cat /var/run/moat.pid)
    if ps -p $pid > /dev/null; then
        echo "Moat is running (PID: $pid)"
    else
        echo "Moat is not running (stale PID file)"
    fi
else
    echo "Moat is not running"
fi
```

### Viewing Logs

In daemon mode, logs are split:
- **stdout** (`/var/log/moat.out`) - Application logs (info, debug, warn, error from the logger)
- **stderr** (`/var/log/moat.err`) - Panic messages and other stderr output

```bash
# Tail application logs (primary log file)
tail -f /var/log/moat.out

# Tail error output (panics, system errors)
tail -f /var/log/moat.err

# View both logs simultaneously
tail -f /var/log/moat.out /var/log/moat.err
```

**Note**: When running in daemon mode, the application logger writes to stdout for better log organization. In non-daemon mode, logs go to stderr (standard behavior).

## Security Considerations

### Privilege Dropping

When running as daemon with a privileged user (e.g., root) to bind to ports < 1024 or attach XDP programs, it's recommended to drop privileges after initialization:

```bash
moat --daemon \
  --daemon-user nobody \
  --daemon-group daemon \
  --iface eth0 --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key"
```

This will:
1. Start as root (or privileged user)
2. Bind to privileged ports (80, 443)
3. Attach XDP programs to network interfaces
4. Drop privileges to `nobody:daemon`
5. Continue running as unprivileged user

### File Permissions

Ensure proper permissions for daemon files:

```bash
# Create log directory
sudo mkdir -p /var/log/moat
sudo chown nobody:daemon /var/log/moat
sudo chmod 755 /var/log/moat

# Create PID directory
sudo mkdir -p /var/run
sudo chmod 755 /var/run

# Set up log files
sudo touch /var/log/moat.out /var/log/moat.err
sudo chown nobody:daemon /var/log/moat.out /var/log/moat.err
sudo chmod 644 /var/log/moat.out /var/log/moat.err
```

## Systemd Integration

Create a systemd service file for easier management:

```ini
# /etc/systemd/system/moat.service
[Unit]
Description=Moat Reverse Proxy and Firewall
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/moat.pid
ExecStart=/usr/local/bin/moat --daemon --config /etc/moat/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/moat /var/run

[Install]
WantedBy=multi-user.target
```

Manage with systemd:

```bash
# Enable service
sudo systemctl enable moat

# Start service
sudo systemctl start moat

# Stop service
sudo systemctl stop moat

# Restart service
sudo systemctl restart moat

# View status
sudo systemctl status moat

# View logs
sudo journalctl -u moat -f
```

## Implementation Details

### Architecture

The daemon mode implementation uses a two-phase startup:

1. **Pre-daemonization phase**:
   - Parse command line arguments
   - Load configuration
   - Validate settings
   - If daemon mode enabled, call `daemonize()` before starting Tokio runtime

2. **Post-daemonization phase**:
   - Initialize logger
   - Start Tokio runtime
   - Run application logic

This ensures daemonization happens before any async operations, as required by the `daemonize` crate.

### Key Files Modified

- `Cargo.toml` - Added `daemonize = "0.5.0"` dependency
- `src/cli.rs` - Added `DaemonConfig` struct and CLI arguments
- `src/main.rs` - Restructured to support pre-tokio daemonization
- `config.yaml` - Added daemon configuration section
- `config_example.yaml` - Added daemon examples
- `README.md` - Added daemon mode documentation

### Signal Handling

The application already has proper signal handling with `tokio::signal::ctrl_c()`. When running as daemon:

- SIGINT (Ctrl+C) triggers graceful shutdown
- SIGTERM triggers graceful shutdown
- XDP programs are properly detached on shutdown

## Troubleshooting

### Daemon Won't Start

Check:
1. Log files for errors: `cat /var/log/moat.err`
2. Permissions on log directory and PID file location
3. User/group exists: `id nobody`
4. Configuration file is valid: `moat --config /etc/moat/config.yaml` (without `--daemon`)

### Permission Denied Errors

If you see permission errors:
- Ensure log directory is writable by daemon user
- Ensure PID file location is writable
- Check that user/group specified exists
- Verify file system permissions

### Stale PID File

If daemon won't start due to existing PID file:
```bash
# Check if process is actually running
ps -p $(cat /var/run/moat.pid)

# If not running, remove stale PID file
sudo rm /var/run/moat.pid

# Then start daemon
moat --daemon --config /etc/moat/config.yaml
```

## References

- [daemonize crate documentation](https://docs.rs/daemonize/latest/daemonize/)
- [Moat README](README.md)
- [Configuration Examples](config_example.yaml)

