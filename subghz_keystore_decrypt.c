/**
 * @file subghz_keystore_decrypt.c
 * @brief Decrypt a SubGhz keystore file on the device.
 *
 * This is a developer/inspection tool for your own Flipper Zero. It takes an
 * encrypted SubGhz keystore file (the ones that ship in
 * /ext/subghz/assets, e.g. keeloq_mfcodes, nice_flor_s, came_atomo,
 * alutech_at_4n), decrypts it using the device secure enclave + AES engine
 * (the same slot-1 key the firmware uses), and writes the decrypted result
 * next to the original with a ".decrypted" suffix.
 *
 * Two keystore layouts are supported:
 *   - "Flipper SubGhz Keystore File"     -> text records KEY:TYPE:NAME
 *       (decrypted by the public subghz_keystore_load / _get_data API)
 *   - "Flipper SubGhz Keystore RAW File" -> continuous AES-CBC blob
 *       (decrypted here chunk by chunk with the crypto HAL, then a few
 *       blocks are cross-checked against subghz_keystore_raw_get_data, see
 *       raw_self_check())
 *
 * The output is written to "<name>.decrypted.tmp" first and only moved to
 * "<name>.decrypted" after everything succeeded, so a failed or cancelled
 * decryption never touches a previous result. Note that storage "rename" is
 * really delete-destination + copy, so the final move is guarded by a free
 * space check and a size verification (see commit_output()).
 *
 * WARNING: the enclave key for these files is the same on every device, so
 * the output does not reveal anything device-unique - but it DOES contain
 * plaintext manufacturer keys (e.g. KeeLoq manufacturer codes). The firmware
 * library explicitly asks not to share them: keep the .decrypted files to
 * yourself and do not publish them.
 */

#include <stddef.h>

#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_crypto.h>

#include <gui/gui.h>
#include <gui/view.h>
#include <gui/view_holder.h>
#include <gui/elements.h>
#include <storage/storage.h>
#include <dialogs/dialogs.h>
#include <toolbox/hex.h>
#include <toolbox/path.h>
#include <toolbox/stream/stream.h>
#include <flipper_format/flipper_format.h>
#include <flipper_format/flipper_format_i.h>

#include <lib/subghz/subghz_keystore.h>

#define TAG "KeystoreDecrypt"

#define KEYSTORE_FILE_TYPE     "Flipper SubGhz Keystore File"
#define KEYSTORE_RAW_FILE_TYPE "Flipper SubGhz Keystore RAW File"
#define KEYSTORE_FILE_VERSION  0

// Same enclave key slot the firmware uses for these assets.
#define KEYSTORE_ENCRYPTION_KEY_SLOT 1

// Encryption field values (mirrors SubGhzKeystoreEncryption in the library).
#define ENCRYPTION_NONE   0
#define ENCRYPTION_AES256 1

#define AES_BLOCK_SIZE 16

// Must match stack_size in application.fam (only used for the log line).
#define APP_STACK_SIZE 4096u

#define ASSETS_FOLDER   EXT_PATH("subghz/assets")
#define FALLBACK_FOLDER EXT_PATH("subghz")
#define OUTPUT_SUFFIX   ".decrypted"
#define TEMP_SUFFIX     ".tmp"
#define CHECK_SUFFIX    ".chk"

// Must be a multiple of the AES block size.
#define BIN_CHUNK_SIZE 256
#define READ_BUF_SIZE  128

/** Working buffers for the RAW decryptor (kept off the 4K app stack). */
typedef struct {
    uint8_t bin[BIN_CHUNK_SIZE]; // ciphertext, must be 4-byte aligned
    uint8_t dec[BIN_CHUNK_SIZE]; // plaintext, must be 4-byte aligned
    uint8_t read_buf[READ_BUF_SIZE];
    char hex_out[BIN_CHUNK_SIZE * 2];
} RawBuffers;

_Static_assert(BIN_CHUNK_SIZE % AES_BLOCK_SIZE == 0, "chunk must be whole AES blocks");
_Static_assert(offsetof(RawBuffers, dec) % 4 == 0, "dec must be 4-byte aligned");

/** Plaintext blocks remembered during RAW decryption for raw_self_check(). */
typedef struct {
    uint8_t first[16]; // block at offset 0
    uint8_t second_chunk[16]; // first block of the 2nd chunk (offset BIN_CHUNK_SIZE)
    uint8_t last_chunk[16]; // first block of the last chunk
    size_t last_chunk_offset;
    uint8_t last[16]; // last block of the file
} RawCheckpoints;

typedef enum {
    DecryptResultOk,
    DecryptResultCancelled,
    DecryptResultCantOpenInput,
    DecryptResultBadHeader,
    DecryptResultUnsupportedType,
    DecryptResultUnsupportedVersion,
    DecryptResultNotEncrypted,
    DecryptResultUnknownEncryption,
    DecryptResultCantWriteOutput,
    DecryptResultEnclaveFailed,
    DecryptResultDecryptFailed,
    DecryptResultBadData,
    DecryptResultNoKeys,
    DecryptResultSelfCheckFailed,
    DecryptResultKeptTemp,
    DecryptResultOwnOutput,
} DecryptResult;

static const char* decrypt_result_text(DecryptResult r) {
    switch(r) {
    case DecryptResultOk:
        return "Done";
    case DecryptResultCancelled:
        return "Cancelled";
    case DecryptResultCantOpenInput:
        return "Can't open input";
    case DecryptResultBadHeader:
        return "Bad/missing header";
    case DecryptResultUnsupportedType:
        return "Not a keystore file";
    case DecryptResultUnsupportedVersion:
        return "Unsupported version";
    case DecryptResultNotEncrypted:
        return "File is not encrypted";
    case DecryptResultUnknownEncryption:
        return "Unknown encryption";
    case DecryptResultCantWriteOutput:
        return "Can't write output";
    case DecryptResultEnclaveFailed:
        return "Enclave key load failed";
    case DecryptResultDecryptFailed:
        return "Decrypt/parse failed";
    case DecryptResultBadData:
        return "Malformed data";
    case DecryptResultNoKeys:
        return "No keys decrypted";
    case DecryptResultSelfCheckFailed:
        return "Self-check mismatch";
    case DecryptResultOwnOutput:
        return "This is an output of\nthis app. Pick the\noriginal keystore";
    case DecryptResultKeptTemp:
        return "Move failed, result\nkept as *" OUTPUT_SUFFIX TEMP_SUFFIX;
    default:
        return "Unknown error";
    }
}

/**
 * The IV transform the firmware applies to a keystore IV before loading the
 * enclave key with it (subghz_keystore_mess_with_iv() in the firmware, which
 * is static and can't be called from an app): each byte except the first one
 * has the original value of the byte before it added, modulo 256. Walking from
 * the last byte down keeps the original values of the lower bytes available.
 *
 * The RAW decryptor cross-checks its output against the firmware's own
 * subghz_keystore_raw_get_data(), so if this ever disagrees with the firmware
 * the user gets "Self-check mismatch" instead of silently wrong output.
 */
static void keystore_transform_iv(uint8_t* iv) {
    for(size_t i = AES_BLOCK_SIZE - 1; i > 0; i--) {
        iv[i] = (uint8_t)(iv[i] + iv[i - 1]);
    }
}

/* ---------------------------------------------------------------------------
 * Progress screen (shown while working; Back requests cancellation)
 * ------------------------------------------------------------------------- */

typedef struct {
    uint8_t percent; // 0..100, or PROGRESS_UNKNOWN
    bool cancellable;
    bool cancelling;
} ProgressModel;

#define PROGRESS_UNKNOWN 0xFF

typedef struct {
    ViewHolder* view_holder;
    View* view;
    volatile bool cancel_requested; // written by the GUI thread, read by the app thread
} Progress;

static void progress_draw_callback(Canvas* canvas, void* model) {
    ProgressModel* m = model;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 14, AlignCenter, AlignCenter, "Decrypting...");
    canvas_set_font(canvas, FontSecondary);
    if(m->percent != PROGRESS_UNKNOWN) {
        elements_progress_bar(canvas, 8, 26, 112, m->percent / 100.0f);
    } else {
        canvas_draw_str_aligned(canvas, 64, 32, AlignCenter, AlignCenter, "Please wait");
    }
    if(m->cancelling) {
        canvas_draw_str_aligned(canvas, 64, 54, AlignCenter, AlignCenter, "Cancelling...");
    } else if(m->cancellable) {
        canvas_draw_str_aligned(canvas, 64, 54, AlignCenter, AlignCenter, "Back: cancel");
    }
}

static bool progress_input_callback(InputEvent* event, void* context) {
    Progress* progress = context;
    if(event->key == InputKeyBack && event->type == InputTypeShort) {
        bool cancellable = false;
        with_view_model(
            progress->view,
            ProgressModel * m,
            {
                cancellable = m->cancellable;
                if(cancellable) m->cancelling = true;
            },
            true);
        if(cancellable) progress->cancel_requested = true;
    }
    // Swallow every key so Back never leaks to the view holder.
    return true;
}

static Progress* progress_alloc(Gui* gui) {
    Progress* progress = malloc(sizeof(Progress));
    progress->cancel_requested = false;
    progress->view = view_alloc();
    view_allocate_model(progress->view, ViewModelTypeLocking, sizeof(ProgressModel));
    view_set_context(progress->view, progress);
    view_set_draw_callback(progress->view, progress_draw_callback);
    view_set_input_callback(progress->view, progress_input_callback);
    with_view_model(
        progress->view,
        ProgressModel * m,
        {
            m->percent = PROGRESS_UNKNOWN;
            m->cancellable = false;
            m->cancelling = false;
        },
        false);

    progress->view_holder = view_holder_alloc();
    view_holder_set_view(progress->view_holder, progress->view);
    view_holder_attach_to_gui(progress->view_holder, gui);
    return progress;
}

static void progress_free(Progress* progress) {
    view_holder_set_view(progress->view_holder, NULL);
    view_holder_free(progress->view_holder);
    view_free(progress->view);
    free(progress);
}

static void progress_set(Progress* progress, uint8_t percent, bool cancellable) {
    with_view_model(
        progress->view,
        ProgressModel * m,
        {
            m->percent = percent;
            m->cancellable = cancellable;
        },
        true);
}

static bool progress_is_cancelled(Progress* progress) {
    return progress->cancel_requested;
}

/* ---------------------------------------------------------------------------
 * Decryption
 * ------------------------------------------------------------------------- */

typedef struct {
    Storage* storage;
    const char* input_path;
    const char* output_path; // temporary file, renamed by the caller on success
    const char* check_path; // scratch file for the RAW self-check (created and removed internally)
    Progress* progress;

    // Results reported back to the caller
    bool is_raw;
    size_t records_expected; // text: non-empty encrypted lines in the file
    size_t records_written; // text: records actually decoded and written
    size_t bytes_written; // raw: plaintext bytes written
    bool raw_layout_ok; // raw: blob laid out the way the firmware reads it
} DecryptJob;

static bool file_write_all(File* file, const void* data, size_t len) {
    return storage_file_write(file, data, len) == len;
}

static void hex_encode(const uint8_t* in, size_t len, char* out) {
    static const char hex_chars[] = "0123456789ABCDEF";
    for(size_t i = 0; i < len; i++) {
        out[i * 2] = hex_chars[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex_chars[in[i] & 0xF];
    }
}

// Real keystores are a few KB; anything far larger is not one.
#define KEYSTORE_MAX_FILE_SIZE (1024 * 1024)
// "Filetype:" must appear this early: it is line 1 in every file the firmware
// writes; the margin allows a block of leading "#" comments.
#define KEYSTORE_SNIFF_SIZE    2048

/**
 * Cheap pre-check before flipper_format parsing. Now that the whole SD card
 * can be browsed, the user may pick a big unrelated file, and flipper_format
 * would scan all of it looking for a "Filetype" key on the uncancellable
 * progress screen. Reject by size and by a "Filetype:" sniff instead.
 */
static DecryptResult keystore_quick_check(Storage* storage, const char* path) {
    FileInfo info;
    if(storage_common_stat(storage, path, &info) != FSE_OK) return DecryptResultCantOpenInput;
    if(info.size > KEYSTORE_MAX_FILE_SIZE) return DecryptResultUnsupportedType;

    DecryptResult result = DecryptResultUnsupportedType;
    char* buf = malloc(KEYSTORE_SNIFF_SIZE + 1);
    File* file = storage_file_alloc(storage);
    if(!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        result = DecryptResultCantOpenInput;
    } else {
        size_t got = storage_file_read(file, buf, KEYSTORE_SNIFF_SIZE);
        buf[got] = '\0';
        // strstr stops at an embedded NUL, which only makes binaries fail faster.
        if(strstr(buf, "Filetype:")) result = DecryptResultOk;
    }
    storage_file_free(file); // closes it if open
    free(buf);
    return result;
}

/**
 * Open the input and validate the common keystore header:
 * Filetype, Version, Encryption (must be AES256) and IV.
 * On success `ff` is positioned right after the IV value.
 */
static DecryptResult
    keystore_read_header(FlipperFormat* ff, const char* path, bool* is_raw, uint8_t* iv) {
    DecryptResult result = DecryptResultOk;
    FuriString* filetype = furi_string_alloc();

    do {
        uint32_t version = 0;
        uint32_t encryption = 0;

        if(!flipper_format_file_open_existing(ff, path)) {
            result = DecryptResultCantOpenInput;
            break;
        }
        if(!flipper_format_read_header(ff, filetype, &version)) {
            result = DecryptResultBadHeader;
            break;
        }
        if(furi_string_cmp_str(filetype, KEYSTORE_RAW_FILE_TYPE) == 0) {
            *is_raw = true;
        } else if(furi_string_cmp_str(filetype, KEYSTORE_FILE_TYPE) == 0) {
            *is_raw = false;
        } else {
            result = DecryptResultUnsupportedType;
            break;
        }
        if(version != KEYSTORE_FILE_VERSION) {
            result = DecryptResultUnsupportedVersion;
            break;
        }
        if(!flipper_format_read_uint32(ff, "Encryption", &encryption, 1)) {
            result = DecryptResultBadHeader;
            break;
        }
        if(encryption == ENCRYPTION_NONE) {
            result = DecryptResultNotEncrypted;
            break;
        }
        if(encryption != ENCRYPTION_AES256) {
            result = DecryptResultUnknownEncryption;
            break;
        }
        if(!flipper_format_read_hex(ff, "IV", iv, AES_BLOCK_SIZE)) {
            result = DecryptResultBadHeader;
            break;
        }
    } while(false);

    furi_string_free(filetype);
    return result;
}

/**
 * Count the non-empty lines left in the stream, using the same notion of a
 * "line" as the library: anything but CR/LF makes a line non-empty.
 */
static size_t count_remaining_records(Stream* stream, uint8_t* buf, size_t buf_size) {
    size_t records = 0;
    bool line_has_data = false;
    size_t got;
    while((got = stream_read(stream, buf, buf_size)) > 0) {
        for(size_t i = 0; i < got; i++) {
            if(buf[i] == '\n') {
                if(line_has_data) records++;
                line_has_data = false;
            } else if(buf[i] != '\r') {
                line_has_data = true;
            }
        }
    }
    if(line_has_data) records++;
    return records;
}

/**
 * Load the enclave key, but only while core2 is alive.
 *
 * furi_hal_crypto_enclave_load_key() returns false WITHOUT releasing the
 * crypto mutex when core2 is not alive, and a failed load must not be followed
 * by unload_key(), so calling it with a dead core2 would block every crypto
 * user until reboot. The HAL can't be changed from this app, so check first.
 * (A core2 crash between this check and the load is not covered.)
 */
static bool enclave_load_key_safe(const uint8_t* iv) {
    if(!furi_hal_bt_is_alive()) {
        FURI_LOG_E(TAG, "Core2 is not alive, not touching the enclave");
        return false;
    }
    return furi_hal_crypto_enclave_load_key(KEYSTORE_ENCRYPTION_KEY_SLOT, iv);
}

/**
 * Check that the enclave key can be loaded with this IV. The library's
 * subghz_keystore_load() reports success even when the key load fails, so we
 * have to probe it ourselves to give a meaningful error.
 */
static bool enclave_probe(const uint8_t* file_iv) {
    uint8_t iv[AES_BLOCK_SIZE] __attribute__((aligned(4)));
    memcpy(iv, file_iv, sizeof(iv));
    keystore_transform_iv(iv);
    if(!enclave_load_key_safe(iv)) return false;
    furi_hal_crypto_enclave_unload_key(KEYSTORE_ENCRYPTION_KEY_SLOT);
    return true;
}

/**
 * Decrypt a "Flipper SubGhz Keystore File" (KEY:TYPE:NAME records).
 * `ff` has already been validated by keystore_read_header() and is consumed
 * (closed) here because the library re-opens the file by path.
 */
static DecryptResult
    decrypt_text_keystore(DecryptJob* job, FlipperFormat* ff, const uint8_t* file_iv) {
    DecryptResult result = DecryptResultOk;
    SubGhzKeystore* keystore = NULL;
    File* out = NULL;
    bool out_open = false;

    // The library gives no progress feedback and can't be interrupted.
    progress_set(job->progress, PROGRESS_UNKNOWN, false);

    do {
        uint8_t buf[64];
        job->records_expected =
            count_remaining_records(flipper_format_get_raw_stream(ff), buf, sizeof(buf));
        flipper_format_file_close(ff);

        if(job->records_expected == 0) {
            result = DecryptResultNoKeys;
            break;
        }
        if(!enclave_probe(file_iv)) {
            result = DecryptResultEnclaveFailed;
            break;
        }

        // The library loads the enclave key itself: same core2 guard as above.
        if(!furi_hal_bt_is_alive()) {
            result = DecryptResultEnclaveFailed;
            break;
        }
        keystore = subghz_keystore_alloc();
        if(!subghz_keystore_load(keystore, job->input_path)) {
            // Header and enclave were validated above, so what is left is an
            // AES failure or a malformed (overlong) record line.
            result = DecryptResultDecryptFailed;
            break;
        }
        SubGhzKeyArray_t* data = subghz_keystore_get_data(keystore);
        if(SubGhzKeyArray_size(*data) == 0) {
            result = DecryptResultNoKeys;
            break;
        }

        out = storage_file_alloc(job->storage);
        if(!storage_file_open(out, job->output_path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
            result = DecryptResultCantWriteOutput;
            break;
        }
        out_open = true;

        // Plain (Encryption: 0) keystore, loadable by subghz_keystore_load().
        static const char header[] = "Filetype: " KEYSTORE_FILE_TYPE "\n"
                                     "Version: 0\n"
                                     "Encryption: 0\n";
        if(!file_write_all(out, header, sizeof(header) - 1)) {
            result = DecryptResultCantWriteOutput;
            break;
        }

        char line[128];
        for
            M_EACH(key, *data, SubGhzKeyArray_t) {
                // Same record format the library writes in subghz_keystore_save().
                int len = snprintf(
                    line,
                    sizeof(line),
                    "%08lX%08lX:%hu:%s\n",
                    (unsigned long)(key->key >> 32),
                    (unsigned long)(key->key & 0xFFFFFFFF),
                    key->type,
                    furi_string_get_cstr(key->name));
                if(len <= 0 || len >= (int)sizeof(line)) {
                    result = DecryptResultBadData;
                    break;
                }
                if(!file_write_all(out, line, len)) {
                    result = DecryptResultCantWriteOutput;
                    break;
                }
                job->records_written++;
            }
    } while(false);

    if(out) {
        if(out_open && !storage_file_close(out) && result == DecryptResultOk) {
            result = DecryptResultCantWriteOutput;
        }
        storage_file_free(out);
    }
    if(keystore) subghz_keystore_free(keystore);
    return result;
}

/**
 * Remember the plaintext blocks of one decrypted chunk that raw_self_check()
 * will compare. `offset` is the file offset of `dec[0]`, `len` a non-zero
 * multiple of AES_BLOCK_SIZE.
 */
static void
    raw_remember_checkpoints(RawCheckpoints* cp, size_t offset, const uint8_t* dec, size_t len) {
    if(offset == 0) memcpy(cp->first, dec, AES_BLOCK_SIZE);
    if(offset == BIN_CHUNK_SIZE) memcpy(cp->second_chunk, dec, AES_BLOCK_SIZE);
    memcpy(cp->last_chunk, dec, AES_BLOCK_SIZE);
    cp->last_chunk_offset = offset;
    memcpy(cp->last, dec + len - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
}

/**
 * Decrypt a "Flipper SubGhz Keystore RAW File" (continuous AES-CBC blob).
 * `ff` has already been validated by keystore_read_header(). Streams the hex
 * ciphertext, decrypts it chunk by chunk (the AES engine keeps the CBC state
 * between furi_hal_crypto_decrypt() calls while the key stays loaded) and
 * writes the plaintext back out as hex in an Encryption: 0 RAW file, which is
 * the input format of subghz_keystore_raw_encrypted_save().
 *
 * `cp` receives the plaintext blocks needed by raw_self_check().
 */
static DecryptResult decrypt_raw_keystore(
    DecryptJob* job,
    FlipperFormat* ff,
    const uint8_t* file_iv,
    RawCheckpoints* cp) {
    DecryptResult result = DecryptResultOk;
    FuriString* encrypt_data = furi_string_alloc();
    RawBuffers* b = malloc(sizeof(RawBuffers));
    File* out = NULL;
    bool out_open = false;
    bool key_loaded = false;

    do {
        // Consume the "Encrypt_data: RAW" key; the hex blob follows it. The
        // parser below skips CR/LF/whitespace, so no manual newline skipping.
        if(!flipper_format_read_string(ff, "Encrypt_data", encrypt_data)) {
            result = DecryptResultBadHeader;
            break;
        }
        furi_string_trim(encrypt_data); // read_line keeps trailing spaces/tabs
        if(furi_string_cmp_str(encrypt_data, "RAW") != 0) {
            result = DecryptResultBadHeader;
            break;
        }
        Stream* stream = flipper_format_get_raw_stream(ff);
        const size_t data_start = stream_tell(stream);
        const size_t data_size = stream_size(stream) - data_start;

        out = storage_file_alloc(job->storage);
        if(!storage_file_open(out, job->output_path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
            result = DecryptResultCantWriteOutput;
            break;
        }
        out_open = true;

        // The comment line is skipped by flipper_format, so the result is still
        // accepted by subghz_keystore_raw_encrypted_save().
        static const char header[] =
            "Filetype: " KEYSTORE_RAW_FILE_TYPE "\n"
            "Version: 0\n"
            "# Trailing 00 bytes may be zero padding added at encryption time\n"
            "Encryption: 0\n";
        if(!file_write_all(out, header, sizeof(header) - 1)) {
            result = DecryptResultCantWriteOutput;
            break;
        }

        uint8_t iv[AES_BLOCK_SIZE] __attribute__((aligned(4)));
        memcpy(iv, file_iv, sizeof(iv));
        keystore_transform_iv(iv);
        if(!enclave_load_key_safe(iv)) {
            result = DecryptResultEnclaveFailed;
            break;
        }
        key_loaded = true;

        size_t bin_len = 0; // decoded bytes pending in b->bin
        bool high_nibble = true; // next hex digit fills the high nibble
        uint8_t cur_byte = 0;

        // Firmware layout tracking. subghz_keystore_raw_get_data() skips
        // exactly one byte after the "Encrypt_data: RAW" value (the '\n') and
        // then indexes the hex digits by position, so it only reads the blob
        // correctly when the digits are contiguous. We accept any whitespace,
        // but remember whether the layout is firmware-compatible.
        size_t blob_pos = 0; // byte index in the blob
        bool seen_hex = false;
        bool space_after_hex = false;
        job->raw_layout_ok = true;
        size_t consumed = 0;
        uint8_t last_percent = PROGRESS_UNKNOWN;

        while(result == DecryptResultOk) {
            if(progress_is_cancelled(job->progress)) {
                result = DecryptResultCancelled;
                break;
            }
            size_t got = stream_read(stream, b->read_buf, sizeof(b->read_buf));
            if(got == 0) break;
            consumed += got;

            uint8_t percent = data_size ? (uint8_t)((uint64_t)consumed * 100 / data_size) : 100;
            if(percent > 100) percent = 100;
            if(percent != last_percent) {
                progress_set(job->progress, percent, true);
                last_percent = percent;
            }

            for(size_t i = 0; i < got; i++, blob_pos++) {
                const char c = (char)b->read_buf[i];
                uint8_t nibble;
                if(!hex_char_to_hex_nibble(c, &nibble)) {
                    // Ignore newlines / whitespace, reject anything else.
                    if(c == '\r' || c == '\n' || c == ' ' || c == '\t') {
                        if(blob_pos == 0) {
                            // the one byte the firmware skips
                        } else if(!seen_hex) {
                            job->raw_layout_ok = false; // extra leading whitespace
                        } else {
                            space_after_hex = true; // fine if nothing follows
                        }
                        continue;
                    }
                    result = DecryptResultBadData;
                    break;
                }
                // The firmware would skip this digit, or a gap precedes it.
                if(blob_pos == 0 || space_after_hex) job->raw_layout_ok = false;
                seen_hex = true;
                if(high_nibble) {
                    cur_byte = (uint8_t)(nibble << 4);
                    high_nibble = false;
                    continue;
                }
                b->bin[bin_len++] = cur_byte | nibble;
                high_nibble = true;
                if(bin_len < BIN_CHUNK_SIZE) continue;

                if(!furi_hal_crypto_decrypt(b->bin, b->dec, bin_len)) {
                    result = DecryptResultDecryptFailed;
                    break;
                }
                raw_remember_checkpoints(cp, job->bytes_written, b->dec, bin_len);
                hex_encode(b->dec, bin_len, b->hex_out);
                if(!file_write_all(out, b->hex_out, bin_len * 2)) {
                    result = DecryptResultCantWriteOutput;
                    break;
                }
                job->bytes_written += bin_len;
                bin_len = 0;
            }
        }
        if(result != DecryptResultOk) break;

        // Ciphertext must be a whole number of AES blocks, with no dangling
        // half-byte, and must not be empty.
        if(!high_nibble || (bin_len % AES_BLOCK_SIZE) != 0) {
            result = DecryptResultBadData;
            break;
        }
        if(bin_len > 0) {
            if(!furi_hal_crypto_decrypt(b->bin, b->dec, bin_len)) {
                result = DecryptResultDecryptFailed;
                break;
            }
            raw_remember_checkpoints(cp, job->bytes_written, b->dec, bin_len);
            hex_encode(b->dec, bin_len, b->hex_out);
            if(!file_write_all(out, b->hex_out, bin_len * 2)) {
                result = DecryptResultCantWriteOutput;
                break;
            }
            job->bytes_written += bin_len;
        }
        if(job->bytes_written == 0) {
            result = DecryptResultBadData;
            break;
        }
    } while(false);

    if(key_loaded) furi_hal_crypto_enclave_unload_key(KEYSTORE_ENCRYPTION_KEY_SLOT);
    if(out) {
        if(out_open && !storage_file_close(out) && result == DecryptResultOk) {
            result = DecryptResultCantWriteOutput;
        }
        storage_file_free(out);
    }
    free(b);
    furi_string_free(encrypt_data);
    return result;
}

/**
 * Compare one plaintext block at `offset` with what the firmware library
 * itself decrypts there.
 */
static DecryptResult raw_check_block(const char* path, size_t offset, const uint8_t* expected) {
    uint8_t reference[AES_BLOCK_SIZE];
    // raw_get_data loads the enclave key itself: guard core2 (see enclave_load_key_safe).
    if(!furi_hal_bt_is_alive()) return DecryptResultEnclaveFailed;
    if(!subghz_keystore_raw_get_data(path, offset, reference, sizeof(reference)) ||
       memcmp(reference, expected, sizeof(reference)) != 0) {
        return DecryptResultSelfCheckFailed;
    }
    return DecryptResultOk;
}

/**
 * Cross-check the RAW decryption against subghz_keystore_raw_get_data(), the
 * code the firmware uses to read these files. For offset >= 16 the library
 * decrypts a block with the previous ciphertext block as IV, independently of
 * our streaming.
 *
 * In CBC decryption P[i] = D(C[i]) ^ C[i-1], so if the chaining state were
 * lost between two of our furi_hal_crypto_decrypt() calls, only the FIRST
 * block of the following chunk would be wrong. Hence the checked blocks:
 *  - offset 0: the key and our keystore_transform_iv();
 *  - first block of the 2nd chunk: chaining across a chunk boundary (a HAL
 *    chaining problem would be systematic, so one boundary is representative);
 *  - first block of the last chunk: the same, at the far end of the file;
 *  - the last block: total length / block alignment of what we parsed.
 * Duplicate offsets (small files) are checked once.
 */
static DecryptResult
    raw_self_check(const char* path, const DecryptJob* job, const RawCheckpoints* cp) {
    const size_t total = job->bytes_written;
    struct {
        size_t offset;
        const uint8_t* block;
    } checks[] = {
        {0, cp->first},
        {BIN_CHUNK_SIZE, cp->second_chunk},
        {cp->last_chunk_offset, cp->last_chunk},
        {total - AES_BLOCK_SIZE, cp->last},
    };
    const size_t checks_count = COUNT_OF(checks);

    for(size_t i = 0; i < checks_count; i++) {
        if(checks[i].offset >= total) continue; // e.g. no 2nd chunk
        bool duplicate = false;
        for(size_t j = 0; j < i; j++) {
            if(checks[j].offset == checks[i].offset) duplicate = true;
        }
        if(duplicate) continue;
        DecryptResult result = raw_check_block(path, checks[i].offset, checks[i].block);
        if(result != DecryptResultOk) return result;
    }
    return DecryptResultOk;
}

/**
 * Write a copy of a RAW keystore whose hex blob has whitespace inside it, in
 * the layout the firmware library can read (same header and IV, digits
 * contiguous right after "Encrypt_data: RAW\n"), so that raw_self_check() can
 * still verify the key and our IV transform on such files.
 */
static bool
    raw_write_normalized_copy(Storage* storage, const char* input_path, const char* copy_path) {
    bool ok = false;
    bool is_raw = false;
    uint8_t iv[AES_BLOCK_SIZE];
    FlipperFormat* in = flipper_format_file_alloc(storage);
    FlipperFormat* out = flipper_format_file_alloc(storage);
    FuriString* value = furi_string_alloc();
    uint8_t* buf = malloc(READ_BUF_SIZE);

    do {
        if(keystore_read_header(in, input_path, &is_raw, iv) != DecryptResultOk || !is_raw) break;
        if(!flipper_format_read_string(in, "Encrypt_data", value)) break;

        if(!flipper_format_file_open_always(out, copy_path)) break;
        if(!flipper_format_write_header_cstr(out, KEYSTORE_RAW_FILE_TYPE, KEYSTORE_FILE_VERSION))
            break;
        uint32_t encryption = ENCRYPTION_AES256;
        if(!flipper_format_write_uint32(out, "Encryption", &encryption, 1)) break;
        if(!flipper_format_write_hex(out, "IV", iv, AES_BLOCK_SIZE)) break;
        // Ends with '\n', the one byte raw_get_data() skips.
        if(!flipper_format_write_string_cstr(out, "Encrypt_data", "RAW")) break;

        Stream* src = flipper_format_get_raw_stream(in);
        Stream* dst = flipper_format_get_raw_stream(out);
        ok = true;
        size_t got;
        while(ok && (got = stream_read(src, buf, READ_BUF_SIZE)) > 0) {
            size_t digits = 0;
            for(size_t i = 0; i < got; i++) {
                uint8_t nibble;
                if(hex_char_to_hex_nibble((char)buf[i], &nibble)) buf[digits++] = buf[i];
            }
            if(digits && stream_write(dst, buf, digits) != digits) ok = false;
        }
    } while(false);

    free(buf);
    furi_string_free(value);
    flipper_format_free(out);
    flipper_format_free(in);
    return ok;
}

/**
 * Validate the header once and dispatch to the matching decryptor.
 */
static DecryptResult decrypt_keystore_file(DecryptJob* job) {
    uint8_t iv[AES_BLOCK_SIZE] __attribute__((aligned(4)));
    RawCheckpoints cp = {0};

    DecryptResult result = keystore_quick_check(job->storage, job->input_path);
    if(result != DecryptResultOk) return result;

    FlipperFormat* ff = flipper_format_file_alloc(job->storage);
    result = keystore_read_header(ff, job->input_path, &job->is_raw, iv);
    if(result == DecryptResultOk) {
        if(job->is_raw) {
            result = decrypt_raw_keystore(job, ff, iv, &cp);
        } else {
            result = decrypt_text_keystore(job, ff, iv);
        }
    }
    flipper_format_free(ff); // closes the input before the self-check re-opens it

    if(result == DecryptResultOk && job->is_raw) {
        if(job->raw_layout_ok) {
            result = raw_self_check(job->input_path, job, &cp);
        } else {
            // The library would read the original blob at the wrong
            // positions, so verify against a normalized copy instead.
            FURI_LOG_W(TAG, "RAW data has line breaks: checking a normalized copy");
            if(raw_write_normalized_copy(job->storage, job->input_path, job->check_path)) {
                result = raw_self_check(job->check_path, job, &cp);
            } else {
                result = DecryptResultCantWriteOutput;
            }
            // Remove it right away (also after a partial write); only this
            // branch ever creates it.
            storage_common_remove(job->storage, job->check_path);
        }
    }
    return result;
}

/* ---------------------------------------------------------------------------
 * Output commit
 * ------------------------------------------------------------------------- */

// Slack for FAT cluster rounding of the copied file.
#define COMMIT_SPACE_MARGIN (64 * 1024)

/**
 * Move the finished temp file over the final output.
 *
 * storage_common_rename() is not atomic: it deletes the destination, copies
 * the source and deletes the source, and the copy can be silently truncated
 * when the card fills up. So:
 *  - refuse up front (keeping any previous result) if the copy can't fit;
 *  - judge success by the size of the copy, not by the rename status (which
 *    is also an error when only deleting the source failed);
 *  - if the copy is bad, drop it but keep the temp file, because by then the
 *    previous result is already gone and the temp file is the only copy.
 *
 * @return DecryptResultOk, DecryptResultCantWriteOutput (nothing changed,
 *         temp may be removed) or DecryptResultKeptTemp (keep the temp file).
 */
static DecryptResult
    commit_output(Storage* storage, const char* temp_path, const char* output_path) {
    FileInfo temp_info;
    if(storage_common_stat(storage, temp_path, &temp_info) != FSE_OK) {
        return DecryptResultCantWriteOutput;
    }

    uint64_t free_space = 0;
    if(storage_common_fs_info(storage, STORAGE_EXT_PATH_PREFIX, NULL, &free_space) != FSE_OK) {
        return DecryptResultCantWriteOutput;
    }
    // The old result is deleted before the copy starts, so its space counts.
    FileInfo old_info;
    if(storage_common_stat(storage, output_path, &old_info) == FSE_OK) {
        free_space += old_info.size;
    }
    if(free_space < temp_info.size + COMMIT_SPACE_MARGIN) {
        FURI_LOG_E(TAG, "Not enough space to commit output");
        return DecryptResultCantWriteOutput;
    }

    FS_Error rename_error = storage_common_rename(storage, temp_path, output_path);
    FileInfo out_info;
    // FSE_INTERNAL is what rename returns when only deleting the source failed
    // after a complete copy; any other error means the copy may never have
    // happened and a same-sized file there could be the old result.
    if((rename_error == FSE_OK || rename_error == FSE_INTERNAL) &&
       storage_common_stat(storage, output_path, &out_info) == FSE_OK &&
       out_info.size == temp_info.size) {
        // Complete copy. A leftover temp (source delete failed) is removed by the caller.
        if(rename_error != FSE_OK) FURI_LOG_W(TAG, "Rename reported %d", rename_error);
        return DecryptResultOk;
    }

    // Missing or truncated copy: never leave a truncated result behind.
    if(storage_file_exists(storage, output_path)) storage_common_remove(storage, output_path);
    return storage_file_exists(storage, temp_path) ? DecryptResultKeptTemp :
                                                     DecryptResultCantWriteOutput;
}

/* ---------------------------------------------------------------------------
 * Entry point
 * ------------------------------------------------------------------------- */

/** Files this app writes next to the keystores (FAT names: case-insensitive). */
static bool is_own_output(const FuriString* path) {
    return furi_string_end_withi(path, OUTPUT_SUFFIX) ||
           furi_string_end_withi(path, OUTPUT_SUFFIX TEMP_SUFFIX) ||
           furi_string_end_withi(path, OUTPUT_SUFFIX CHECK_SUFFIX);
}

/**
 * File browser item callback. The browser API can only filter by extension
 * (and the keystores have none), it can't hide items, so instead the files
 * that can't be decrypted are marked by name:
 *   "[out] ..." - this app's own outputs (.decrypted / .tmp / .chk)
 *   "[ex] ..."  - *.example templates shipped in the assets folder
 * Runs in the browser worker thread; only touches its arguments.
 */
static bool
    browser_item_callback(FuriString* path, void* context, uint8_t** icon, FuriString* item_name) {
    UNUSED(context);
    UNUSED(icon);
    const char* tag = NULL;
    if(is_own_output(path)) {
        tag = "[out] ";
    } else if(furi_string_end_withi(path, ".example")) {
        tag = "[ex] ";
    }
    if(tag) {
        path_extract_filename(path, item_name, false);
        furi_string_replace_at(item_name, 0, 0, tag);
    }
    // No custom icon: the browser keeps the default one, and uses the plain
    // file name when item_name is left empty.
    return false;
}

static void show_message(DialogsApp* dialogs, const char* header, const char* text) {
    DialogMessage* message = dialog_message_alloc();
    dialog_message_set_header(message, header, 64, 2, AlignCenter, AlignTop);
    dialog_message_set_text(message, text, 64, 34, AlignCenter, AlignCenter);
    dialog_message_set_buttons(message, NULL, "OK", NULL);
    dialog_message_show(dialogs, message);
    dialog_message_free(message);
}

static bool confirm_overwrite(DialogsApp* dialogs) {
    DialogMessage* message = dialog_message_alloc();
    dialog_message_set_header(message, "Overwrite?", 64, 2, AlignCenter, AlignTop);
    dialog_message_set_text(
        message,
        OUTPUT_SUFFIX " file already\nexists. Replace it?",
        64,
        30,
        AlignCenter,
        AlignCenter);
    dialog_message_set_buttons(message, "Cancel", NULL, "Replace");
    DialogMessageButton button = dialog_message_show(dialogs, message);
    dialog_message_free(message);
    return button == DialogMessageButtonRight;
}

int32_t subghz_keystore_decrypt_main(void* p) {
    UNUSED(p);

    Storage* storage = furi_record_open(RECORD_STORAGE);
    DialogsApp* dialogs = furi_record_open(RECORD_DIALOGS);
    Gui* gui = furi_record_open(RECORD_GUI);

    // Start in the assets folder (or the closest existing parent).
    const char* start_path = ASSETS_FOLDER;
    if(!storage_dir_exists(storage, start_path)) {
        start_path = storage_dir_exists(storage, FALLBACK_FOLDER) ? FALLBACK_FOLDER :
                                                                    STORAGE_EXT_PATH_PREFIX;
    }

    FuriString* input_path = furi_string_alloc_set(start_path);
    // Folder the browser opens in; also its base_path (see below).
    FuriString* browse_dir = furi_string_alloc_set(start_path);
    FuriString* output_path = furi_string_alloc();
    FuriString* temp_path = furi_string_alloc();
    FuriString* check_path = furi_string_alloc();

    DialogsFileBrowserOptions browser_options;
    // "*" shows every file; the keystore assets have no extension.
    dialog_file_browser_set_basic_options(&browser_options, "*", NULL);
    browser_options.hide_dot_files = true;
    browser_options.skip_assets = false;
    browser_options.item_loader_callback = browser_item_callback;
    browser_options.item_loader_context = NULL;

    while(true) {
        // The browser closes on Back when it is in base_path, and Left goes up
        // a level regardless of base_path (up to /ext). Making base_path the
        // folder it opens in gives: Back = exit right away, Left = browse the
        // rest of the SD card, Back inside a subfolder = up a level as usual.
        browser_options.base_path = furi_string_get_cstr(browse_dir);
        if(!dialog_file_browser_show(dialogs, input_path, input_path, &browser_options)) break;
        // Next time open (and exit from) the folder of the file just picked.
        path_extract_dirname(furi_string_get_cstr(input_path), browse_dir);

        if(is_own_output(input_path)) {
            // Decrypting our own output would only end in "not encrypted"
            // and could stack up *.decrypted.decrypted files.
            show_message(dialogs, "Wrong file", decrypt_result_text(DecryptResultOwnOutput));
            continue;
        }

        furi_string_printf(output_path, "%s" OUTPUT_SUFFIX, furi_string_get_cstr(input_path));
        furi_string_printf(temp_path, "%s" TEMP_SUFFIX, furi_string_get_cstr(output_path));
        furi_string_printf(check_path, "%s" CHECK_SUFFIX, furi_string_get_cstr(output_path));

        if(storage_file_exists(storage, furi_string_get_cstr(output_path)) &&
           !confirm_overwrite(dialogs)) {
            continue; // back to the file browser
        }

        DecryptJob job = {
            .storage = storage,
            .input_path = furi_string_get_cstr(input_path),
            .output_path = furi_string_get_cstr(temp_path),
            .check_path = furi_string_get_cstr(check_path),
        };

        job.progress = progress_alloc(gui);
        progress_set(job.progress, PROGRESS_UNKNOWN, false);
        DecryptResult result = decrypt_keystore_file(&job);
        if(result == DecryptResultOk) {
            // Still behind the progress screen: free space query and copy can be slow.
            progress_set(job.progress, PROGRESS_UNKNOWN, false);
            result = commit_output(
                storage, furi_string_get_cstr(temp_path), furi_string_get_cstr(output_path));
        }
        progress_free(job.progress);
        job.progress = NULL;

        // Only ever remove our own temporary file, never an older result, and
        // keep it when it is the only remaining copy of the output.
        if(result != DecryptResultKeptTemp &&
           storage_file_exists(storage, furi_string_get_cstr(temp_path))) {
            storage_common_remove(storage, furi_string_get_cstr(temp_path));
        }

        FURI_LOG_I(
            TAG,
            "Decrypt %s -> %s: %s",
            furi_string_get_cstr(input_path),
            furi_string_get_cstr(output_path),
            decrypt_result_text(result));
        // Lowest free stack seen so far (see stack_size in application.fam).
        FURI_LOG_I(
            TAG,
            "Stack free min: %lu of %u bytes",
            (unsigned long)furi_thread_get_stack_space(furi_thread_get_current_id()),
            APP_STACK_SIZE);

        if(result == DecryptResultOk) {
            FuriString* body = furi_string_alloc();
            if(job.is_raw && !job.raw_layout_ok) {
                furi_string_printf(
                    body,
                    "RAW: %zu bytes. Note:\nline breaks in data,\nfirmware can't read it",
                    job.bytes_written);
            } else if(job.is_raw) {
                furi_string_printf(
                    body, "RAW: %zu bytes\nSaved as *" OUTPUT_SUFFIX, job.bytes_written);
            } else if(job.records_written < job.records_expected) {
                furi_string_printf(
                    body,
                    "Only %zu of %zu keys!\nSaved as *" OUTPUT_SUFFIX,
                    job.records_written,
                    job.records_expected);
            } else {
                furi_string_printf(
                    body, "%zu keys\nSaved as *" OUTPUT_SUFFIX, job.records_written);
            }
            const char* header = "Success";
            if(!job.is_raw && job.records_written < job.records_expected) {
                header = "Partial";
            }
            show_message(dialogs, header, furi_string_get_cstr(body));
            furi_string_free(body);
        } else if(result != DecryptResultCancelled) {
            show_message(dialogs, "Failed", decrypt_result_text(result));
        }
        // Back to the browser (positioned on the file just processed) so the
        // next keystore can be decrypted; Back in the browser exits the app.
    }

    furi_string_free(check_path);
    furi_string_free(temp_path);
    furi_string_free(output_path);
    furi_string_free(browse_dir);
    furi_string_free(input_path);

    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_DIALOGS);
    furi_record_close(RECORD_STORAGE);

    return 0;
}
