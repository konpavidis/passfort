# Passfort

A secure command-line password manager written in Rust. Passfort lets you store, retrieve, and manage passwords locally with AES-256-GCM encryption. It offers both a traditional CLI interface and an interactive text-based UI, complete with password generation and service search features.

## Features

- **Secure Storage**: Encrypts passwords using AES-256-GCM with a key derived from a master password via Argon2.
- **CLI and UI Modes**: Use subcommands (`add`, `get`, `list`, `search`) or an interactive menu (`ui`).
- **Password Generation**: Automatically generates strong, random alphanumeric passwords.
- **Search Functionality**: Find stored services by partial name match.
- **Local Storage**: Saves encrypted data in a JSON file (`passwords.json`) with restrictive permissions.

## Installation

### Prerequisites

- Rust (stable) and Cargo (install via [rustup](https://rustup.rs/)).
- A Unix-like system (e.g., Linux, macOS) for file permission settings (Windows support is partial).

### Build and Install

1. Clone the repository:
   ```bash
   git clone https://github.com/konpavidis/passfort.git
   cd passfort
   ```
2. Build the release version:
   ```bash
   cargo build --release
   ```
3. Install the binary
   ```bash
   cargo install --path .
   ```
## Usage 
Passfort is invoked as pf and requires a master password on each run to derive the encryption key.
#### CLI Mode
  1. Add a password
     ```bash
     pf add <service> <username> <password or [--length <number>] >
     ```
     - Example: pf add github myuser mypass (or --lenght 12)
  2. Get a password
     ```bash
     pf get <service>
     ```
  3. List services
     ```bash
     pf list
     ```

## Notes
Enter your master password when prompted. Use the same password across sessions to access your data.
If you forget your master password, data in passwords.json cannot be recovered—delete the file to start fresh.

### File Structure
- passwords.json: Stores encrypted passwords and a salt (created in the working directory).
- Permissions are set to 600 (owner read/write only) on Unix systems.

### Security
- Encryption: AES-256-GCM with unique nonces per password.
- Key Derivation: Argon2id from the master password and a random salt.
- Storage: Local file, no network access.
