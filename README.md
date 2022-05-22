**MCDL** is a tool that downloads minecraft client from official CDN and generates launch script for it. It is a replacement for bloated proprietary launchers. Just run simple python script and play any version of the game you want.

## Features
- FOSS
- Single simple hackable script
- Windows, Linux, Mac support
- MC 1.13 - 1.19 support
- Vanilla game from official sources
- Incremental download
- Verifies files on disk

## Dependencies
- `python 3` for the script
- `java 17` for the game itself

## Examples
- `./mcdl.py --list-versions`
- `./mcdl.py -v 1.18 -n MyName -o game_dir`
