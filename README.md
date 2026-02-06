# My Adblocker

A Manifest V3 Chrome/Edge extension that blocks ads via network rules and cosmetic filtering.

## Features
- Network-level ad blocking using declarativeNetRequest
- Cosmetic filtering to hide ad containers
- Whitelist support for trusted sites
- Blocking statistics

## Installation

### From Source (Developer Mode)
1. Clone this repository
2. Open `chrome://extensions` (or `edge://extensions`)
3. Enable "Developer Mode"
4. Click "Load Unpacked" and select the `my-adblocker/` folder

## Project Structure
- `manifest.json` - Extension configuration
- `background.js` - Service worker for blocking logic
- `content.js` - Cosmetic filtering scripts
- `rules/` - Network blocking rules
- `popup/` - Extension popup UI

## Development Roadmap
See [adblocker_1.md](adblocker_1.md) for the MVP roadmap.
See [adblocker_2.md](adblocker_2.md) for advanced features.

## Contributing
Pull requests welcome! Please open an issue first to discuss changes.

## License
[GPL-3.0](LICENSE)
