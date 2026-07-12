/* ScaleFS C ABI — recovery SDK groundwork.
 *
 * Link against the `scalefs_ffi` cdylib or staticlib (build with
 * `cargo build -p scalefs-ffi --release`). The ABI is C; any language
 * with a C FFI can call it.
 *
 * Contract:
 *   - ABI compatibility is gated by scalefs_abi_version(): additive
 *     growth (new functions, new JSON fields) does not bump it;
 *     incompatible changes do. Check it once at startup.
 *   - Structured results are UTF-8, NUL-terminated JSON strings.
 *     Every returned char* EXCEPT scalefs_version() is owned by the
 *     caller: free it with scalefs_string_free(). JSON object keys
 *     only ever GROW; parse tolerantly.
 *   - On failure, pointer-returning functions return NULL and int-
 *     returning functions return -1; scalefs_last_error() then holds
 *     a human-readable message for the calling thread (also caller-
 *     freed). Panics never cross the boundary.
 *   - Salvage sessions are STRUCTURALLY READ-ONLY: devices are opened
 *     with probe opens (no locks, no claims) behind a write-refusing
 *     device layer. A session never alters the supplied media.
 *   - A session handle may move between threads; concurrent calls on
 *     one handle serialize internally.
 */

#ifndef SCALEFS_H
#define SCALEFS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- library identity --- */

/* The ABI version this header describes. */
#define SCALEFS_ABI_VERSION_EXPECTED 1u

uint32_t scalefs_abi_version(void);
uint32_t scalefs_format_version(void);
/* Static string; do NOT free. */
const char *scalefs_version(void);

/* --- errors and ownership --- */

/* The calling thread's last error message (caller-owned; free it), or
 * NULL when none is recorded. The next failure overwrites it. */
char *scalefs_last_error(void);
/* Free any caller-owned string returned by this library. NULL ok. */
void scalefs_string_free(char *text);

/* --- forensic salvage (structurally read-only) --- */

typedef struct ScalefsSalvage ScalefsSalvage;

/* Open a salvage session over `count` member paths (image files or
 * raw devices — supply everything you have; roles are reported).
 * view_tx pins the assembled view to that transaction id; 0 adopts
 * the newest that works. NULL on failure. */
ScalefsSalvage *scalefs_salvage_open(const char *const *paths,
                                     size_t count,
                                     uint64_t view_tx);
void scalefs_salvage_close(ScalefsSalvage *session);

/* The assembly report:
 * {"pool_id"?,"label"?,
 *  "features":{"compat","ro_compat","incompat",
 *              "unknown_incompat","unknown_ro_compat"},
 *  "rung":"strict-equivalent"|"partial-roster"|"commit-root"|null,
 *  "view_tx"?,
 *  "devices":[{"index","pool_id"?,"device_id"?,
 *              "slots":[2 x "valid"|"corrupt: …"|"unreadable: …"],
 *              "newest_tx"?,"member"?,
 *              "role":"member"|"orphan"|"shadowed"|"foreign"|
 *                     "unidentified","notes"?}],
 *  "missing":[{"member","device_id","newest_tx"}],
 *  "candidates":[{"tx","kind":"roster"|"commit","adopted","note"?}],
 *  "notes"?}
 * When "unknown_incompat" is true the session is identity-only:
 * nothing past the superblocks is guessed. */
char *scalefs_salvage_report_json(ScalefsSalvage *session);

/* A full reachability pass:
 * {"items","files","directories","damage",
 *  "disconnected":[inode…]}  (inodes with no reachable name) */
char *scalefs_salvage_survey_json(ScalefsSalvage *session);

/* List a directory by path ("/" is the root):
 * {"path","entries":[{"name","kind":"file"|"directory"|"symlink"|
 *  "special","inode"}],"complete":bool}
 * "complete":false means lost tree regions overlapped the directory —
 * entries may be missing. */
char *scalefs_salvage_ls_json(ScalefsSalvage *session, const char *path);

/* Stat a path:
 * {"outcome":"found","inode","size","mode","uid","gid"} |
 * {"outcome":"missing"} | {"outcome":"lost","damage":N} */
char *scalefs_salvage_stat_json(ScalefsSalvage *session, const char *path);

/* Salvage one file to dest_path (created/truncated on the HOST
 * filesystem — never on the salvaged media). Unrecoverable ranges are
 * written as zeros, never skipped, so the output size is exact; the
 * returned JSON is the evidence:
 * {"size","bytes_lost",
 *  "rollup":"intact"|"healed-from-copy"|"reconstructed-from-parity"|
 *           "lost"|"map-lost",
 *  "ranges":[{"offset","len","verdict",…verdict fields:"copy"?,
 *             "reasons"?:[string…]}],
 *  "map_damage":N} */
char *scalefs_salvage_copy_file(ScalefsSalvage *session,
                                const char *source_path,
                                const char *dest_path);

/* Recoverable snapshots:
 * {"snapshots":[{"tx","name","created_at_ns"}],"damage":N} */
char *scalefs_salvage_snapshots_json(ScalefsSalvage *session);

/* Re-root the session on the snapshot with transaction id `tx`
 * (see scalefs_salvage_snapshots_json); subsequent ls/stat/copy calls
 * serve that snapshot's tree. 0 on success, -1 on failure. */
int32_t scalefs_salvage_enter_snapshot(ScalefsSalvage *session,
                                       uint64_t tx);
/* Return to the live tree. 0 on success. */
int32_t scalefs_salvage_enter_live(ScalefsSalvage *session);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SCALEFS_H */
