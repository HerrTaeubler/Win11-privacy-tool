# Windows 11 Privacy Optimizer

A PowerShell script to optimize privacy settings in Windows 11.

## Features

- Restriction of Windows Update Delivery Optimization
- Blocking of telemetry and tracking domains via hosts file
- Optimization of Windows privacy settings
- Backup and restore functionality for all changes

## Installation

Open PowerShell as administrator and run the following command:

irm https://raw.githubusercontent.com/HerrTaeubler/Win11-privacy-tool/main/Win11-privacy-tool.ps1 | iex

## Functions

- Automatic detection of Windows version
- Backup of all changes
- User-friendly menu
- Detailed logging function

## Requirements

- Windows 11
- PowerShell 5.1 or higher
- Administrator rights

## Features in Detail

1. Windows Update Delivery Optimization
   - Restricts peer-to-peer updates to local network only
   - Limits upload bandwidth

2. Host File Blocking
   - Blocks known telemetry and tracking domains
   - Creates automatic backup of hosts file
   - Includes comprehensive list of Microsoft telemetry endpoints

3. Privacy Settings
   - Disables telemetry collection
   - Restricts app diagnostics
   - Disables advertising ID
   - Manages app permissions
   - Controls Windows feedback settings

4. Additional Features
   - Automatic system compatibility check
   - Detailed logging of all changes
   - Easy restore functionality
   - User-friendly interface

## Security

The script automatically creates backups of all changes and allows for easy restoration.

## Compatibility

This script is specifically designed for Windows 11 but may work on Windows 10 with limited functionality.

## License

MIT License

## Author

Herr Täubler

## Disclaimer

Use this script at your own risk. While efforts have been made to ensure safe operation, the author is not responsible for any potential issues that may arise from using this script.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
