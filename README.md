# Directory Opus WebDAV VFS Plugin

> **Seamlessly integrate WebDAV storage into your native file manager.** 
> A high-performance Virtual File System (VFS) plugin for Directory Opus, providing native support for WebDAV. 

[![Download Pre-compiled Binary](https://img.shields.io/badge/Download-Pre--compiled%20Binary%20(.dll)-brightgreen?style=for-the-badge)](https://xiumu.gumroad.com/l/dopus-webdav)

🔥 **Supported Protocols:**
Works out-of-the-box with **standard WebDAV, Nextcloud, OwnCloud, Synology NAS, AList**, and any other storage system supporting the WebDAV protocol. 

## Features

- **Native Remote Browsing**: Navigate through your WebDAV shares natively using the standard Directory Opus lister. 
- **Secure Connections**: Full support for both `dav://` (HTTP) and `davs://` (HTTPS) protocols. 
- **Full File Management**: Supports standard file operations including listing, copying, moving, renaming, and deleting. 
- **Integrated Authentication**: Features an internal credential cache and supports standard URL-embedded credentials.

## Installation

**Option A: Pre-compiled Binary**
Don't want to mess with compilers? You can download the ready-to-use `.dll` file from my Gumroad page. 
👉 **[Download Pre-compiled Binary (.dll) Here](https://xiumu.gumroad.com/l/dopus-webdav)** *(Pay what you want, including $0)*

**Option B: The Developer Way (Build it yourself)**
1. Clone this repository. 
2. Download `pugiconfig.hpp`, `pugixml.cpp`, and `pugixml.hpp` into the project folder. 
3. Run the following command in a Visual Studio developer prompt:

```cmd
cl.exe /MT /O2 /EHsc /utf-8 /LD DOpusWebDAV.cpp pugixml.cpp WebDAVClient.cpp /link /DEF:DOpusWebDAV.def /OUT:DOpusWebDAV.dll
```

4. Copy the compiled DOpusWebDAV.dll to your Directory Opus VFSPlugins directory.   
5. Restart Directory Opus.

##  Usage
Access your WebDAV servers directly from the Directory Opus location bar:

- `davs://user:password@domain.com:8443/path`
- `dav://domain.com/path`

---
*Disclaimer: This is a third-party plugin and is not officially affiliated with GP Software.*