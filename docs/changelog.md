v1.1:
First public release.
- Decrypts text and RAW SubGhz keystores with the device enclave key
- Writes `<name>.decrypted` next to the original via a temporary file, asks before overwriting
- RAW output is cross-checked against the firmware keystore library
- Progress screen; RAW decryption can be cancelled with Back
- File browser: Back exits, Left goes up a folder; own outputs and examples are marked
- Several files can be decrypted in one session
