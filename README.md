# Windows 11 Privacy Optimizer   

![License: MIT](https://img.shields.io/github/license/HerrTaeubler/Win11-privacy-tool)

A PowerShell script to optimize privacy settings in Windows 11.

This tool aims to restrict Windows' data collection and telemetry as much as possible while maintaining system stability and functionality. It provides a balanced approach between privacy and usability, ensuring Windows remains fully operational while minimizing unnecessary data transmission.

## Features
- Restriction of Windows Update Delivery Optimization
- Blocking of telemetry and tracking domains via hosts file
- Comprehensive Windows privacy settings optimization
- Enhanced Windows Search privacy controls
- Dedicated App Permissions Management
- Backup and restore functionality for all changes
- Detailed logging system

## Installation
Open PowerShell as administrator and run the following command:

```irm https://raw.githubusercontent.com/HerrTaeubler/Win11-privacy-tool/main/Win11-privacy-tool.ps1 | iex```


## Functions
- Automatic detection of Windows version and build
- Backup of all changes (current session)
- Optional System Restore Point creation before applying changes (user prompt)
- User-friendly menu interface
- Detailed logging function with different severity levels

## Requirements
- PowerShell 5.1 or higher
- Administrator rights

## Features in Detail

### Windows Update Delivery Optimization
- Restricts peer-to-peer updates to local network only
- Limits upload bandwidth

### Host File Blocking
- Blocks known telemetry and tracking domains
- Creates automatic backup of hosts file
- Includes comprehensive list of Microsoft telemetry endpoints

### Privacy Settings
- Disables telemetry collection
- Restricts app diagnostics
- Disables advertising ID
- Controls Windows Search privacy
- Manages app permissions
- Controls cloud sync settings
- Manages Windows Hello settings
- Controls Timeline and activity history
- Disables unnecessary services
- Manages Windows feedback settings
- Controls clipboard history
- Manages language settings
- Controls content delivery


### App Permissions Management
- Microphone access
- Camera access
- Account information access
- Contacts access
- Calendar access
- Phone call access
- Radio/Bluetooth access
- File system access
- Documents/Pictures/Videos/Music library access
- Email and Tasks access
- Chat/Messaging access
- Downloads folder access
- Screen capture and Screenshot capabilities

### Additional Features
- Automatic system compatibility check
- Detailed logging of all changes
- Easy restore functionality
- Build-specific optimizations

## Roadmap
- [ ] GUI implementation (in progress)
- [ ] Enhanced logging features
- [ ] Additional privacy controls


## Security
The script automatically creates backups of all changes and allows for easy restoration through:
- System Restore Point (optional)
- Registry backups (current session)
- Hosts file backup

## Compatibility
This script is specifically designed for Windows 11 but may work on Windows 10 with limited functionality. 

## License
MIT License

## Author
Herr Täubler

## Disclaimer
Use this script at your own risk. While efforts have been made to ensure safe operation, I am not responsible for any potential issues that may arise from using this script.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
