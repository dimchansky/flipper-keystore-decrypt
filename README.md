# Keystore Decrypt

A Flipper Zero app that decrypts the SubGhz keystore files shipped in
`/ext/subghz/assets` (`keeloq_mfcodes`, `nice_flor_s`, `came_atomo`,
`alutech_at_4n`, ...) on the device itself and saves the plaintext next to the
original as `<name>.decrypted`.

It uses the same secure-enclave key slot and the same library code the stock
firmware uses to read these files, so nothing secret is copied off the device
to do it.

**Please do not publish the decrypted files.** They contain manufacturer keys,
and the firmware authors explicitly ask not to share them. This app is meant for
inspecting your own device.

## Supported formats

- **Flipper SubGhz Keystore File**: text records `KEY:TYPE:NAME`. Decrypted
  with the firmware's own keystore library; the output is a plain
  (`Encryption: 0`) keystore that the firmware can load.
- **Flipper SubGhz Keystore RAW File**: one continuous AES-CBC blob. Decrypted
  chunk by chunk; the output is a plain RAW keystore in hex. Trailing `00` bytes
  may be zero padding added at encryption time.

## Usage

1. Open **Apps → Sub-GHz → Keystore Decrypt**.
2. The file browser opens in `/ext/subghz/assets`. Pick a keystore.
3. Wait for the progress screen (RAW files can be cancelled with **Back**).
4. The result dialog shows how many keys or bytes were decrypted.

The browser returns after each file, so several keystores can be decrypted in
one session.

### Controls in the file browser

- **Back**: exit the app.
- **Left**: go up one folder (the whole SD card can be browsed).
- **OK**: open a folder or pick a file.

Files the app cannot decrypt are marked: `[out]` for its own output files and
`[ex]` for `*.example` templates.

## Safety checks

- The output is written to a temporary file and only replaces an existing
  `.decrypted` file after decryption fully succeeded; you are asked before an
  existing result is overwritten.
- RAW output is cross-checked against the firmware library
  (`subghz_keystore_raw_get_data`): the first block, a chunk boundary, the start
  of the last chunk and the last block.
- Before touching the enclave the app checks that the radio core (core2) is
  running, so a stopped core2 can't leave the crypto engine locked.
- Large or unrelated files are rejected quickly instead of being scanned.

## Building

The app is built with [uFBT](https://pypi.org/project/ufbt/):

```bash
pip install ufbt
ufbt update --channel=release
ufbt
```

To build and launch it on a connected Flipper:

```bash
ufbt launch
```

## License

[MIT](LICENSE).
