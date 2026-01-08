# Zed (SecOps Edition)

Welcome to this custom fork of Zed, which includes the **SecOps Scan** feature for automated security analysis of your code.

---

### Getting Started

#### 1. Clone the Repository
To get started with this project, clone the repository from the main branch:

```bash
git clone https://github.com/coding1100/zed-secops-scan.git
cd zed-secops-scan
```

#### 2. Install Dependencies
Ensure you have the Rust toolchain installed. On Linux, run the following command to install the necessary system dependencies:

```bash
sudo apt-get update && sudo apt-get install -y \
  cmake \
  pkg-config \
  clang \
  libasound2-dev \
  libx11-xcb-dev \
  libxkbcommon-dev \
  libxkbcommon-x11-dev
```

#### 3. Start the Editor
Run the following command to build and start the Zed editor in debug mode:

```bash
source $HOME/.cargo/env
cargo run -p zed --bin zed
```

---

### New Feature: SecOps Scan

The **SecOps Scan** feature allows you to quickly analyze the security posture of any open file using Zed's AI Agent.

#### Key Functionalities:
- **One-Click Security Review**: A shield icon appears in the editor toolbar (top-right, next to search).
- **Auto-Agent Integration**: Automatically opens the Agent panel and creates a new thread if one isn't active.
- **Payload Generation**: Prepends a specialized security prompt to your file contents.
- **Safety Handling**: Large files (>200KB) are automatically truncated, and extremely large files (>1MB) are blocked for safety.
- **Clipboard Sync**: The generated security report prompt is also copied to your clipboard automatically for use in other tools.

#### How to Test:
1. Open a real file (e.g., `main.py` or `requirements.txt`).
2. Look for the **Shield Icon** (🛡️) in the top-right toolbar.
3. Click the icon.
4. **Observe**:
   - The Agent panel focuses.
   - A security analysis prompt and your code are inserted into the chat.
   - A toast notification confirms the action.
   - Try pasting (Ctrl+V) in any other text area to verify the payload was copied to your clipboard.

---

### Contributing
See [CONTRIBUTING.md](./CONTRIBUTING.md) for general Zed contribution guidelines.

### Licensing
Zed is licensed under the GPL-3.0-or-later. See [LICENSE-GPL](./LICENSE-GPL) for details.
