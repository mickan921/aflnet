#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <time.h>

#include "alloc-inl.h"
#include "aflnet.h"

#ifndef _WIN32

int main(void) {
  fprintf(stderr, "aflnet-win-fuzz is only supported on native Windows builds.\n");
  return 1;
}

#else

#include <dbghelp.h>

unsigned int* (*extract_response_codes)(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref) = NULL;
region_t* (*extract_requests)(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref) = NULL;

#ifndef JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
#define JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 0x00002000
#endif

typedef struct {
  char *path;
  u8 *data;
  u32 len;
  region_t *regions;
  u32 region_count;
} seed_t;

typedef struct {
  u8 *data;
  u32 len;
} dict_token_t;

typedef struct {
  PROCESS_INFORMATION pi;
  HANDLE job;
  u8 debug_enabled;
} target_process_t;

typedef struct {
  char *name;
  char *old_value;
  u8 had_old_value;
} env_snapshot_t;

typedef struct {
  char *in_dir;
  char *out_dir;
  char *protocol;
  char *net_config;
  char *coverage_map;
  char *target_cwd;
  char *dictionary_path;
  char **target_env;
  char **target_argv;
  int target_argc;
  u8 net_protocol;
  u8 *net_ip;
  u32 net_port;
  u32 server_wait_usecs;
  u32 poll_wait_msecs;
  u32 socket_timeout_usecs;
  u32 target_shutdown_ms;
  u32 iterations;
  u32 max_run_seconds;
  u32 mutations_per_exec;
  u32 rng_seed;
  u8 rng_seed_given;
  u8 dry_run;
  u8 no_launch;
  u8 minidump;
  u8 crash_on_exit;
  u32 target_env_count;
  dict_token_t *dict_tokens;
  u32 dict_token_count;
} options_t;

typedef struct {
  char *queue_dir;
  char *states_dir;
  char *coverage_dir;
  char *crashes_dir;
  char *hangs_dir;
  char *net_errors_dir;
  char *stats_path;
  char *state_index_path;
  char *coverage_index_path;
  char *crash_index_path;
  char *hang_index_path;
  char *coverage_bits_path;
  char *queue_manifest_path;
  char *exec_log_path;
  time_t start_time;
  u32 total_execs;
  u32 active_seeds;
  u32 queued_paths;
  u32 unique_states;
  u32 unique_coverage;
  u32 saved_crashes;
  u32 saved_hangs;
  u32 saved_net_errors;
  u32 *state_hashes;
  u32 state_hash_count;
  u32 *coverage_hashes;
  u32 coverage_hash_count;
  u32 *crash_hashes;
  u32 crash_hash_count;
  u32 *hang_hashes;
  u32 hang_hash_count;
  u8 *coverage_seen;
  u32 coverage_seen_len;
  const char *stop_reason;
} run_state_t;

static volatile LONG stop_soon;

static void usage(const char *argv0) {
  fprintf(stderr,
          "Usage: %s -i in_dir -o out_dir -N tcp://127.0.0.1/port -P protocol [options] -- target.exe [args]\n"
          "       %s -i in_dir -o out_dir -N tcp://127.0.0.1/port -P protocol --no-launch [options]\n\n"
          "Options:\n"
          "  -D usec   server startup wait before connecting (default: 10000)\n"
          "  -W msec   poll timeout while waiting for each response (default: 1)\n"
          "  -w usec   socket send/receive timeout (default: 1000)\n"
          "  -B file   optional raw coverage bitmap file produced by an instrumented target\n"
          "  -C dir    target working directory (default: current directory)\n"
          "  -E NAME=VALUE\n"
          "            set a target environment variable for launched targets\n"
          "  -X file   AFL-style dictionary file for token overwrite mutations\n"
          "  -t msec   wait for target self-crash after requests before terminating it (default: 250)\n"
          "  -x count  fuzzing iterations, 0 means unlimited (default: 1000)\n"
          "  -V sec    stop after this many seconds, 0 means no time limit (default: 0)\n"
          "  -m count  byte mutations per execution (default: 8)\n"
          "  -Z        dry-run every seed once without mutation, then stop\n"
          "  -S seed   deterministic RNG seed for reproducible fuzzing\n"
          "  --no-launch\n"
          "            fuzz an already-running target; do not pass a target command\n"
          "  --minidump\n"
          "            run launched targets under the Windows debug API and save crash .dmp files\n"
          "  --crash-on-exit\n"
          "            treat nonzero non-exception target exit codes as crashes\n",
          argv0, argv0);
  exit(1);
}

static BOOL WINAPI handle_console_event(DWORD event) {
  switch (event) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
      InterlockedExchange(&stop_soon, 1);
      return TRUE;
    default:
      return FALSE;
  }
}

static u32 parse_u32_option(const char *value, const char *option_name) {
  char *end = NULL;
  unsigned long parsed;

  if (!value || !*value || value[0] == '-') FATAL("Bad value for %s: %s", option_name, value ? value : "(null)");

  errno = 0;
  parsed = strtoul(value, &end, 10);
  if (errno == ERANGE || !end || *end || parsed > UINT_MAX)
    FATAL("Bad value for %s: %s", option_name, value);

  return (u32)parsed;
}

static char *join_path(const char *dir, const char *name) {
  size_t dir_len = strlen(dir);
  size_t name_len = strlen(name);
  int needs_sep = dir_len && dir[dir_len - 1] != '\\' && dir[dir_len - 1] != '/';
  char *ret = (char *)ck_alloc((u32)(dir_len + name_len + needs_sep + 1));

  memcpy(ret, dir, dir_len);
  if (needs_sep) ret[dir_len++] = '\\';
  memcpy(ret + dir_len, name, name_len + 1);
  return ret;
}

static char *absolute_path(const char *path) {
  DWORD needed = GetFullPathNameA(path, 0, NULL, NULL);
  char *ret;

  if (!needed) FATAL("Unable to resolve path '%s' (GetLastError=%lu)", path, GetLastError());

  ret = (char *)ck_alloc(needed);
  if (!GetFullPathNameA(path, needed, ret, NULL))
    FATAL("Unable to resolve path '%s' (GetLastError=%lu)", path, GetLastError());

  return ret;
}

static void ensure_dir(const char *path) {
  if (CreateDirectoryA(path, NULL)) return;
  if (GetLastError() == ERROR_ALREADY_EXISTS) {
    DWORD attrs = GetFileAttributesA(path);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY))
      return;
  }
  FATAL("Unable to create directory '%s'", path);
}

static int dir_exists(const char *path) {
  DWORD attrs = GetFileAttributesA(path);
  return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static int file_exists(const char *path) {
  DWORD attrs = GetFileAttributesA(path);
  return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static int is_absolute_path(const char *path) {
  if (!path || !path[0]) return 0;
  if ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z'))
    return path[1] == ':' && (path[2] == '\\' || path[2] == '/');
  return (path[0] == '\\' && path[1] == '\\') || path[0] == '/';
}

static int has_suffix(const char *str, const char *suffix) {
  size_t str_len = strlen(str);
  size_t suffix_len = strlen(suffix);

  return str_len >= suffix_len && !strcmp(str + str_len - suffix_len, suffix);
}

static int is_artifact_sidecar_name(const char *name) {
  return has_suffix(name, ".txt") ||
         has_suffix(name, ".ps1") ||
         has_suffix(name, ".dmp") ||
         has_suffix(name, ".tmp");
}

static u32 count_files_in_dir(const char *dir) {
  WIN32_FIND_DATAA find_data;
  HANDLE find_handle;
  char *pattern = join_path(dir, "*");
  u32 count = 0;

  find_handle = FindFirstFileA(pattern, &find_data);
  ck_free(pattern);

  if (find_handle == INVALID_HANDLE_VALUE) return 0;

  do {
    if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        !is_artifact_sidecar_name(find_data.cFileName)) count++;
  } while (FindNextFileA(find_handle, &find_data));

  FindClose(find_handle);
  return count;
}

static void read_file(const char *path, u8 **data, u32 *len) {
  FILE *fp = fopen(path, "rb");
  long size;

  if (!fp) PFATAL("Unable to open seed file '%s'", path);
  if (fseek(fp, 0, SEEK_END)) PFATAL("Unable to seek seed file '%s'", path);

  size = ftell(fp);
  if (size <= 0 || (unsigned long)size > UINT_MAX)
    FATAL("Seed file '%s' is empty or too large", path);
  if (fseek(fp, 0, SEEK_SET)) PFATAL("Unable to rewind seed file '%s'", path);

  *data = (u8 *)ck_alloc((u32)size);
  *len = (u32)size;

  if (fread(*data, 1, *len, fp) != *len) PFATAL("Short read from seed file '%s'", path);
  fclose(fp);
}

static int hex_value(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static void add_dict_token(options_t *opts, u8 *data, u32 len) {
  dict_token_t *token;

  if (!len) return;

  opts->dict_tokens = (dict_token_t *)ck_realloc(
      opts->dict_tokens, (opts->dict_token_count + 1) * sizeof(dict_token_t));
  token = &opts->dict_tokens[opts->dict_token_count++];
  token->data = (u8 *)ck_alloc(len);
  token->len = len;
  memcpy(token->data, data, len);
}

static int decode_dict_value(const char *value, int quoted, u8 **data_ref,
                             u32 *len_ref) {
  const char *p = value;
  u8 *data = NULL;
  u32 len = 0;

  while (*p) {
    unsigned char c;

    if (quoted && *p == '"') break;
    if (!quoted && (*p == '\r' || *p == '\n')) break;

    if (*p == '\\') {
      p++;
      if (!*p) break;

      switch (*p) {
        case 'n':
          c = '\n';
          p++;
          break;
        case 'r':
          c = '\r';
          p++;
          break;
        case 't':
          c = '\t';
          p++;
          break;
        case '\\':
        case '"':
          c = (unsigned char)*p++;
          break;
        case 'x':
          if (p[1] && p[2] &&
              hex_value((unsigned char)p[1]) >= 0 &&
              hex_value((unsigned char)p[2]) >= 0) {
            c = (u8)((hex_value((unsigned char)p[1]) << 4) |
                     hex_value((unsigned char)p[2]));
            p += 3;
            break;
          }
          c = (unsigned char)*p++;
          break;
        default:
          c = (unsigned char)*p++;
          break;
      }
    } else {
      c = (unsigned char)*p++;
    }

    data = (u8 *)ck_realloc(data, len + 1);
    data[len++] = c;
  }

  if (!len) {
    if (data) ck_free(data);
    return 1;
  }

  *data_ref = data;
  *len_ref = len;
  return 0;
}

static char *trim_ascii(char *line) {
  char *end;

  while (*line == ' ' || *line == '\t' || *line == '\r' || *line == '\n')
    line++;

  end = line + strlen(line);
  while (end > line &&
         (end[-1] == ' ' || end[-1] == '\t' ||
          end[-1] == '\r' || end[-1] == '\n')) {
    *--end = '\0';
  }

  return line;
}

static void load_dictionary(options_t *opts) {
  FILE *fp;
  char line[4096];

  if (!opts->dictionary_path) return;

  fp = fopen(opts->dictionary_path, "r");
  if (!fp) PFATAL("Unable to open dictionary file '%s'", opts->dictionary_path);

  while (fgets(line, sizeof(line), fp)) {
    char *value = trim_ascii(line);
    char *quote;
    u8 *data = NULL;
    u32 len = 0;

    if (!*value || *value == '#') continue;

    quote = strchr(value, '"');
    if (quote) {
      if (decode_dict_value(quote + 1, 1, &data, &len)) continue;
    } else {
      char *eq = strchr(value, '=');
      if (eq) value = trim_ascii(eq + 1);
      if (decode_dict_value(value, 0, &data, &len)) continue;
    }

    add_dict_token(opts, data, len);
    ck_free(data);
  }

  fclose(fp);

  if (!opts->dict_token_count)
    FATAL("Dictionary '%s' did not contain any usable tokens",
          opts->dictionary_path);
}

static int read_optional_file(const char *path, u8 **data, u32 *len) {
  FILE *fp = fopen(path, "rb");
  long size;

  *data = NULL;
  *len = 0;

  if (!fp) return 0;
  if (fseek(fp, 0, SEEK_END)) {
    fclose(fp);
    return 0;
  }

  size = ftell(fp);
  if (size <= 0 || (unsigned long)size > UINT_MAX) {
    fclose(fp);
    return 0;
  }

  if (fseek(fp, 0, SEEK_SET)) {
    fclose(fp);
    return 0;
  }

  *data = (u8 *)ck_alloc((u32)size);
  *len = (u32)size;

  if (fread(*data, 1, *len, fp) != *len) {
    ck_free(*data);
    *data = NULL;
    *len = 0;
    fclose(fp);
    return 0;
  }

  fclose(fp);
  return 1;
}

static void save_raw_file(const char *path, u8 *buf, u32 len) {
  FILE *fp = fopen(path, "wb");

  if (!fp) PFATAL("Unable to create raw queue file '%s'", path);
  if (fwrite(buf, 1, len, fp) != len) PFATAL("Short write to raw queue file '%s'", path);

  fclose(fp);
}

static char *append_suffix(const char *path, const char *suffix) {
  size_t path_len = strlen(path);
  size_t suffix_len = strlen(suffix);
  char *ret = (char *)ck_alloc((u32)(path_len + suffix_len + 1));

  memcpy(ret, path, path_len);
  memcpy(ret + path_len, suffix, suffix_len + 1);
  return ret;
}

static char *alloc_numbered_suffix_path(const char *path, const char *suffix) {
  u32 i;
  char *candidate = append_suffix(path, suffix);

  if (!file_exists(candidate)) return candidate;
  ck_free(candidate);

  for (i = 1; i < 10000; i++) {
    candidate = alloc_printf("%s%s.%u", path, suffix, i);
    if (!file_exists(candidate)) return candidate;
    ck_free(candidate);
  }

  FATAL("Unable to find an unused rotated path for '%s%s'", path, suffix);
}

static void append_hash_index(const char *path, u32 hash) {
  FILE *fp = fopen(path, "a");

  if (!fp) return;
  fprintf(fp, "%08x\n", hash);
  fclose(fp);
}

static int first_line_equals(const char *path, const char *expected);

static const char *queue_manifest_header(void) {
  return "queue_id\tkind\tqueue_path\tsource_seed\tsignal_hash\tdetail";
}

static void rotate_old_schema_file(const char *path, const char *label) {
  char *rotated_path = alloc_numbered_suffix_path(path, ".old-schema");

  if (!MoveFileExA(path, rotated_path, MOVEFILE_REPLACE_EXISTING)) {
    FATAL("Unable to rotate incompatible %s '%s' to '%s' (GetLastError=%lu)",
          label, path, rotated_path, GetLastError());
  }

  WARNF("Rotated incompatible %s to '%s'", label, rotated_path);
  ck_free(rotated_path);
}

static void ensure_queue_manifest_header(run_state_t *state) {
  FILE *fp;

  if (file_exists(state->queue_manifest_path)) {
    if (first_line_equals(state->queue_manifest_path,
                          queue_manifest_header())) return;
    rotate_old_schema_file(state->queue_manifest_path, "queue manifest");
  }

  fp = fopen(state->queue_manifest_path, "w");
  if (!fp) return;

  fprintf(fp, "%s\n", queue_manifest_header());
  fclose(fp);
}

static void fprint_tsv_field(FILE *fp, const char *value) {
  if (!value) return;

  while (*value) {
    if (*value == '\t' || *value == '\r' || *value == '\n') fputc(' ', fp);
    else fputc(*value, fp);
    value++;
  }
}

static const char *exec_log_header(void) {
  return "exec_id\tseed_path\toutcome\tresponse_bytes\tresponse_states\tcoverage_bytes\tcoverage_new_bits\texit_code\ttarget_pid\tsend_failed\ttarget_timed_out\tcrash_reason\tactive_seeds\tunique_states\tunique_coverage\tsaved_crashes\tsaved_hangs\tsaved_net_errors";
}

static int first_line_equals(const char *path, const char *expected) {
  FILE *fp = fopen(path, "rb");
  char line[1024];
  size_t len;

  if (!fp) return 0;

  if (!fgets(line, sizeof(line), fp)) {
    fclose(fp);
    return 0;
  }

  fclose(fp);
  len = strlen(line);
  while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
    line[--len] = '\0';

  return !strcmp(line, expected);
}

static void ensure_exec_log_header(run_state_t *state) {
  FILE *fp;

  if (file_exists(state->exec_log_path)) {
    if (first_line_equals(state->exec_log_path, exec_log_header())) return;
    rotate_old_schema_file(state->exec_log_path, "execution log");
  }

  fp = fopen(state->exec_log_path, "w");
  if (!fp) return;

  fprintf(fp, "%s\n", exec_log_header());
  fclose(fp);
}

static void append_queue_manifest(run_state_t *state,
                                  const char *kind,
                                  const char *queue_path,
                                  seed_t *seed,
                                  u32 hash,
                                  const char *detail) {
  FILE *fp = fopen(state->queue_manifest_path, "a");

  if (!fp) return;

  fprintf(fp, "%u\t", state->queued_paths);
  fprint_tsv_field(fp, kind);
  fprintf(fp, "\t");
  fprint_tsv_field(fp, queue_path);
  fprintf(fp, "\t");
  fprint_tsv_field(fp, seed->path);
  fprintf(fp, "\t%08x\t", hash);
  fprint_tsv_field(fp, detail ? detail : "");
  fprintf(fp, "\n");

  fclose(fp);
}

static void append_exec_log(run_state_t *state, seed_t *seed,
                            const char *outcome, unsigned int response_len,
                            unsigned int response_state_count,
                            u32 coverage_len, u32 coverage_new_bits,
                            DWORD exit_code, DWORD target_pid,
                            int send_failed, int target_timed_out,
                            const char *crash_reason_text) {
  FILE *fp = fopen(state->exec_log_path, "a");

  if (!fp) return;

  fprintf(fp, "%u\t", state->total_execs);
  fprint_tsv_field(fp, seed ? seed->path : "");
  fprintf(fp, "\t");
  fprint_tsv_field(fp, outcome);
  fprintf(fp, "\t%u\t%u\t%u\t%u\t0x%08lx\t%lu\t%d\t%d\t",
          response_len,
          response_state_count,
          coverage_len,
          coverage_new_bits,
          (unsigned long)exit_code,
          (unsigned long)target_pid,
          send_failed,
          target_timed_out);
  fprint_tsv_field(fp, crash_reason_text ? crash_reason_text : "none");
  fprintf(fp, "\t%u\t%u\t%u\t%u\t%u\t%u\n",
          state->active_seeds,
          state->unique_states,
          state->unique_coverage,
          state->saved_crashes,
          state->saved_hangs,
          state->saved_net_errors);

  fclose(fp);
}

static void load_hash_index(const char *path, u32 **hashes_ref, u32 *count_ref) {
  FILE *fp = fopen(path, "r");
  unsigned int value;

  if (!fp) return;

  while (fscanf(fp, "%x", &value) == 1) {
    *hashes_ref = (u32 *)ck_realloc(*hashes_ref, (*count_ref + 1) * sizeof(u32));
    (*hashes_ref)[*count_ref] = (u32)value;
    (*count_ref)++;
  }

  fclose(fp);
}

static void load_coverage_bits(run_state_t *state) {
  read_optional_file(state->coverage_bits_path,
                     &state->coverage_seen,
                     &state->coverage_seen_len);
}

static u32 note_new_coverage_bits(run_state_t *state, u8 *coverage_buf,
                                  u32 coverage_len) {
  u32 i;
  u32 new_bits = 0;

  if (!coverage_len) return 0;

  if (coverage_len > state->coverage_seen_len) {
    state->coverage_seen = (u8 *)ck_realloc(state->coverage_seen, coverage_len);
    state->coverage_seen_len = coverage_len;
  }

  for (i = 0; i < coverage_len; i++) {
    if (!coverage_buf[i] || state->coverage_seen[i]) continue;
    state->coverage_seen[i] = 1;
    new_bits++;
  }

  if (new_bits) save_raw_file(state->coverage_bits_path,
                              state->coverage_seen,
                              state->coverage_seen_len);

  return new_bits;
}

static void load_seed_dir(const char *in_dir, seed_t **seeds_ref, u32 *seed_count_ref, int required) {
  WIN32_FIND_DATAA find_data;
  HANDLE find_handle;
  char *pattern = join_path(in_dir, "*");
  seed_t *seeds = *seeds_ref;
  u32 seed_count = *seed_count_ref;
  u32 loaded_here = 0;

  find_handle = FindFirstFileA(pattern, &find_data);
  ck_free(pattern);

  if (find_handle == INVALID_HANDLE_VALUE) {
    if (required) FATAL("Unable to list input directory '%s'", in_dir);
    return;
  }

  do {
    char *path;
    seed_t *seed;

    if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    if (!required && is_artifact_sidecar_name(find_data.cFileName)) continue;

    path = join_path(in_dir, find_data.cFileName);
    seeds = (seed_t *)ck_realloc(seeds, (seed_count + 1) * sizeof(seed_t));
    seed = &seeds[seed_count];
    memset(seed, 0, sizeof(*seed));

    seed->path = path;
    read_file(path, &seed->data, &seed->len);
    seed->regions = (*extract_requests)(seed->data, seed->len, &seed->region_count);

    if (!seed->region_count) {
      if (required) FATAL("Seed file '%s' did not produce request regions", path);
      WARNF("Skipping queued input without request regions: %s", path);
      if (seed->data) ck_free(seed->data);
      ck_free(path);
      memset(seed, 0, sizeof(*seed));
      continue;
    }

    seed_count++;
    loaded_here++;
  } while (FindNextFileA(find_handle, &find_data));

  FindClose(find_handle);

  if (required && !loaded_here) FATAL("Input directory '%s' does not contain seed files", in_dir);

  *seeds_ref = seeds;
  *seed_count_ref = seed_count;
}

static void load_seeds(options_t *opts, run_state_t *state, seed_t **seeds_ref, u32 *seed_count_ref) {
  load_seed_dir(opts->in_dir, seeds_ref, seed_count_ref, 1);

  if (dir_exists(state->queue_dir)) {
    u32 before = *seed_count_ref;
    load_seed_dir(state->queue_dir, seeds_ref, seed_count_ref, 0);
    if (*seed_count_ref > before) {
      OKF("Loaded %u resumable queue entries from %s.", *seed_count_ref - before, state->queue_dir);
    }
  }

  state->active_seeds = *seed_count_ref;
}

static region_t *clone_regions(region_t *regions, u32 region_count) {
  region_t *copy;

  if (!region_count) return NULL;

  copy = (region_t *)ck_alloc(region_count * sizeof(region_t));
  memcpy(copy, regions, region_count * sizeof(region_t));
  return copy;
}

static void append_active_seed(run_state_t *state, seed_t **seeds_ref,
                               u32 *seed_count_ref, char *path, u8 *data,
                               u32 len, region_t *regions,
                               u32 region_count) {
  seed_t *seeds;
  seed_t *seed;

  if (!path || !data || !len || !region_count) {
    if (path) ck_free(path);
    return;
  }

  seeds = (seed_t *)ck_realloc(*seeds_ref,
                               (*seed_count_ref + 1) * sizeof(seed_t));
  seed = &seeds[*seed_count_ref];
  memset(seed, 0, sizeof(*seed));

  seed->path = path;
  seed->data = (u8 *)ck_alloc(len);
  memcpy(seed->data, data, len);
  seed->len = len;
  seed->regions = clone_regions(regions, region_count);
  seed->region_count = region_count;

  *seeds_ref = seeds;
  *seed_count_ref = *seed_count_ref + 1;
  state->active_seeds = *seed_count_ref;
}

static char *build_command_line(char **argv, int argc) {
  char *cmd = NULL;
  u32 cmd_len = 0;
  int i;

  for (i = 0; i < argc; i++) {
    const char *arg = argv[i];
    int needs_quotes = !arg[0] || strpbrk(arg, " \t\"") != NULL;
    size_t arg_len = strlen(arg);
    u32 extra = (u32)(arg_len * 2 + 4);
    u32 pos;
    size_t j;
    u32 backslashes = 0;

    cmd = (char *)ck_realloc(cmd, cmd_len + extra + 2);
    pos = cmd_len;

    if (cmd_len) cmd[pos++] = ' ';
    if (needs_quotes) cmd[pos++] = '"';

    if (!needs_quotes) {
      memcpy(cmd + pos, arg, arg_len);
      pos += (u32)arg_len;
    } else {
      for (j = 0; j < arg_len; j++) {
        if (arg[j] == '\\') {
          backslashes++;
          continue;
        }

        if (arg[j] == '"') {
          while (backslashes) {
            cmd[pos++] = '\\';
            cmd[pos++] = '\\';
            backslashes--;
          }
          cmd[pos++] = '\\';
          cmd[pos++] = '"';
        } else {
          while (backslashes) {
            cmd[pos++] = '\\';
            backslashes--;
          }
          cmd[pos++] = arg[j];
        }
      }

      while (backslashes) {
        cmd[pos++] = '\\';
        cmd[pos++] = '\\';
        backslashes--;
      }
    }

    if (needs_quotes) cmd[pos++] = '"';
    cmd[pos] = '\0';
    cmd_len = pos;
  }

  return cmd;
}

static void fprintf_ps_quoted(FILE *fp, const char *str) {
  fputc('\'', fp);
  while (*str) {
    if (*str == '\'') fputc('\'', fp);
    fputc(*str++, fp);
  }
  fputc('\'', fp);
}

static char *dup_range(const char *str, size_t len) {
  char *copy = (char *)ck_alloc((u32)len + 1);

  memcpy(copy, str, len);
  copy[len] = '\0';
  return copy;
}

static const char *env_assignment_value(const char *assignment) {
  const char *eq = strchr(assignment, '=');

  if (!eq || eq == assignment)
    FATAL("Bad syntax used for -E. Expected NAME=VALUE");

  return eq + 1;
}

static char *env_assignment_name(const char *assignment) {
  const char *eq = strchr(assignment, '=');

  if (!eq || eq == assignment)
    FATAL("Bad syntax used for -E. Expected NAME=VALUE");

  return dup_range(assignment, (size_t)(eq - assignment));
}

static void snapshot_and_set_env(env_snapshot_t **snapshots_ref,
                                 u32 *snapshot_count_ref,
                                 const char *name, const char *value) {
  env_snapshot_t snapshot;
  DWORD needed;

  memset(&snapshot, 0, sizeof(snapshot));
  snapshot.name = alloc_printf("%s", name);

  SetLastError(ERROR_SUCCESS);
  needed = GetEnvironmentVariableA(name, NULL, 0);
  if (needed) {
    snapshot.old_value = (char *)ck_alloc(needed);
    snapshot.old_value[0] = '\0';
    SetLastError(ERROR_SUCCESS);
    if (GetEnvironmentVariableA(name, snapshot.old_value, needed) ||
        GetLastError() != ERROR_ENVVAR_NOT_FOUND)
      snapshot.had_old_value = 1;
  } else if (GetLastError() != ERROR_ENVVAR_NOT_FOUND) {
    snapshot.old_value = alloc_printf("%s", "");
    snapshot.had_old_value = 1;
  }

  if (!SetEnvironmentVariableA(name, value))
    FATAL("Unable to set target environment variable '%s' (GetLastError=%lu)",
          name, GetLastError());

  *snapshots_ref = (env_snapshot_t *)ck_realloc(
      *snapshots_ref, (*snapshot_count_ref + 1) * sizeof(env_snapshot_t));
  (*snapshots_ref)[(*snapshot_count_ref)++] = snapshot;
}

static void apply_target_environment(options_t *opts,
                                     env_snapshot_t **snapshots_ref,
                                     u32 *snapshot_count_ref) {
  u32 i;

  *snapshots_ref = NULL;
  *snapshot_count_ref = 0;

  for (i = 0; i < opts->target_env_count; i++) {
    char *name = env_assignment_name(opts->target_env[i]);
    const char *value = env_assignment_value(opts->target_env[i]);

    snapshot_and_set_env(snapshots_ref, snapshot_count_ref, name, value);
    ck_free(name);
  }

  if (opts->coverage_map) {
    snapshot_and_set_env(snapshots_ref, snapshot_count_ref,
                         "AFLNET_COVERAGE_FILE", opts->coverage_map);
  }
}

static void restore_target_environment(env_snapshot_t *snapshots,
                                       u32 snapshot_count) {
  while (snapshot_count) {
    env_snapshot_t *snapshot = &snapshots[--snapshot_count];

    SetEnvironmentVariableA(snapshot->name,
                            snapshot->had_old_value ? snapshot->old_value : NULL);
    if (snapshot->old_value) ck_free(snapshot->old_value);
    ck_free(snapshot->name);
  }

  if (snapshots) ck_free(snapshots);
}

static const char *crash_exit_name(DWORD exit_code) {
  switch (exit_code) {
    case 0xC0000005:
      return "STATUS_ACCESS_VIOLATION";
    case 0xC000001D:
      return "STATUS_ILLEGAL_INSTRUCTION";
    case 0xC000008C:
      return "STATUS_ARRAY_BOUNDS_EXCEEDED";
    case 0xC000008D:
      return "STATUS_FLOAT_DENORMAL_OPERAND";
    case 0xC000008E:
      return "STATUS_FLOAT_DIVIDE_BY_ZERO";
    case 0xC000008F:
      return "STATUS_FLOAT_INEXACT_RESULT";
    case 0xC0000090:
      return "STATUS_FLOAT_INVALID_OPERATION";
    case 0xC0000091:
      return "STATUS_FLOAT_OVERFLOW";
    case 0xC0000092:
      return "STATUS_FLOAT_STACK_CHECK";
    case 0xC0000093:
      return "STATUS_FLOAT_UNDERFLOW";
    case 0xC0000094:
      return "STATUS_INTEGER_DIVIDE_BY_ZERO";
    case 0xC0000095:
      return "STATUS_INTEGER_OVERFLOW";
    case 0xC00000FD:
      return "STATUS_STACK_OVERFLOW";
    case 0xC0000374:
      return "STATUS_HEAP_CORRUPTION";
    case 0xC0000409:
      return "STATUS_STACK_BUFFER_OVERRUN";
    default:
      return (exit_code & 0xC0000000) == 0xC0000000 ?
             "NTSTATUS_SEVERITY_ERROR" : "NON_CRASH_EXIT";
  }
}

static void write_replay_helper(const char *script_path, const char *artifact_path,
                                options_t *opts) {
  FILE *fp = fopen(script_path, "w");

  if (fp) {
    int i;

    fprintf(fp, "param([string]$AFLNetReplay = \".\\aflnet-replay.exe\")\n");
    fprintf(fp, "function Test-AFLNetAbsolutePath([string]$Path) {\n");
    fprintf(fp, "  if ([string]::IsNullOrEmpty($Path)) { return $false }\n");
    fprintf(fp, "  $isDrive = $Path.Length -ge 3 -and $Path[1] -eq ':' -and (($Path[0] -ge 'A' -and $Path[0] -le 'Z') -or ($Path[0] -ge 'a' -and $Path[0] -le 'z'))\n");
    fprintf(fp, "  if ($isDrive) { return $Path[2] -eq '\\' -or $Path[2] -eq '/' }\n");
    fprintf(fp, "  return $Path.StartsWith('\\\\') -or $Path.StartsWith('/')\n");
    fprintf(fp, "}\n");
    fprintf(fp, "$target = $null\n");
    fprintf(fp, "$replayExitCode = 0\n");
    fprintf(fp, "$targetExe = ");
    fprintf_ps_quoted(fp, opts->target_argv[0]);
    fprintf(fp, "\n$targetCwd = ");
    if (opts->target_cwd) fprintf_ps_quoted(fp, opts->target_cwd);
    else fprintf(fp, "$null");
    fprintf(fp, "\n$targetArgs = @(");
    for (i = 1; i < opts->target_argc; i++) {
      if (i > 1) fprintf(fp, ", ");
      fprintf_ps_quoted(fp, opts->target_argv[i]);
    }
    fprintf(fp, ")\n");
    fprintf(fp, "$targetEnv = @{}\n");
    for (i = 0; i < (int)opts->target_env_count; i++) {
      char *name = env_assignment_name(opts->target_env[i]);
      const char *value = env_assignment_value(opts->target_env[i]);

      fprintf(fp, "$targetEnv[");
      fprintf_ps_quoted(fp, name);
      fprintf(fp, "] = ");
      fprintf_ps_quoted(fp, value);
      fprintf(fp, "\n");
      ck_free(name);
    }
    fprintf(fp, "if ($targetCwd -and -not (Test-AFLNetAbsolutePath $targetExe)) {\n");
    fprintf(fp, "  $candidate = Join-Path $targetCwd $targetExe\n");
    fprintf(fp, "  if (Test-Path -LiteralPath $candidate) { $targetExe = $candidate }\n");
    fprintf(fp, "}\n");
    fprintf(fp, "try {\n");
    fprintf(fp, "  $targetStartInfo = [System.Diagnostics.ProcessStartInfo]::new()\n");
    fprintf(fp, "  $targetStartInfo.FileName = $targetExe\n");
    fprintf(fp, "  $targetStartInfo.UseShellExecute = $false\n");
    fprintf(fp, "  if ($targetCwd) { $targetStartInfo.WorkingDirectory = $targetCwd }\n");
    fprintf(fp, "  foreach ($arg in $targetArgs) { [void]$targetStartInfo.ArgumentList.Add($arg) }\n");
    fprintf(fp, "  foreach ($name in $targetEnv.Keys) { $targetStartInfo.EnvironmentVariables[$name] = $targetEnv[$name] }\n");
    fprintf(fp, "  $target = [System.Diagnostics.Process]::Start($targetStartInfo)\n");
    fprintf(fp, "  Start-Sleep -Milliseconds %u\n", (opts->server_wait_usecs + 999) / 1000);
    fprintf(fp, "  $replayArgs = @(");
    fprintf_ps_quoted(fp, artifact_path);
    fprintf(fp, ", ");
    fprintf_ps_quoted(fp, opts->protocol);
    fprintf(fp, ", ");
    fprintf_ps_quoted(fp, opts->net_config);
    fprintf(fp, ", ");
    fprintf(fp, "'%u', '%u')\n", opts->poll_wait_msecs,
            opts->socket_timeout_usecs);
    fprintf(fp, "  $replayStartInfo = [System.Diagnostics.ProcessStartInfo]::new()\n");
    fprintf(fp, "  $replayStartInfo.FileName = $AFLNetReplay\n");
    fprintf(fp, "  $replayStartInfo.UseShellExecute = $false\n");
    fprintf(fp, "  foreach ($arg in $replayArgs) { [void]$replayStartInfo.ArgumentList.Add($arg) }\n");
    fprintf(fp, "  $replay = [System.Diagnostics.Process]::Start($replayStartInfo)\n");
    fprintf(fp, "  $replay.WaitForExit()\n");
    fprintf(fp, "  $replayExitCode = $replay.ExitCode\n");
    fprintf(fp, "} finally {\n");
    fprintf(fp, "  if ($target) { Stop-Process -Id $target.Id -Force -ErrorAction SilentlyContinue }\n");
    fprintf(fp, "}\n");
    fprintf(fp, "exit $replayExitCode\n");
    fclose(fp);
  }
}

static void write_replay_metadata(const char *artifact_path, options_t *opts,
                                  DWORD exit_code, u32 crash_hash,
                                  const char *minidump_path,
                                  const char *reason) {
  char *metadata_path = append_suffix(artifact_path, ".txt");
  char *script_path = append_suffix(artifact_path, ".replay.ps1");
  char *target_cmd = build_command_line(opts->target_argv, opts->target_argc);
  FILE *fp = fopen(metadata_path, "w");

  if (!fp) {
    ck_free(target_cmd);
    ck_free(script_path);
    ck_free(metadata_path);
    return;
  }

  fprintf(fp, "artifact          : %s\n", artifact_path);
  fprintf(fp, "exit_code         : 0x%08lx\n", (unsigned long)exit_code);
  fprintf(fp, "exit_name         : %s\n", crash_exit_name(exit_code));
  fprintf(fp, "crash_reason      : %s\n", reason ? reason : "unknown");
  fprintf(fp, "crash_hash        : %08x\n", crash_hash);
  fprintf(fp, "minidump          : %s\n", minidump_path ? minidump_path : "none");
  fprintf(fp, "protocol          : %s\n", opts->protocol);
  fprintf(fp, "net_config        : %s\n", opts->net_config);
  fprintf(fp, "poll_wait_msecs   : %u\n", opts->poll_wait_msecs);
  fprintf(fp, "socket_timeout_us : %u\n", opts->socket_timeout_usecs);
  fprintf(fp, "target_cwd        : %s\n", opts->target_cwd ? opts->target_cwd : ".");
  fprintf(fp, "target_command    : %s\n", target_cmd);
  fprintf(fp, "target_env_vars   : %u\n", opts->target_env_count);
  for (int i = 0; i < (int)opts->target_env_count; i++)
    fprintf(fp, "target_env_%03d    : %s\n", i, opts->target_env[i]);
  fprintf(fp, "manual_replay     : start the target command, then run:\n");
  fprintf(fp, "manual_replay_cmd : aflnet-replay.exe \"%s\" %s %s %u %u\n",
          artifact_path, opts->protocol, opts->net_config,
          opts->poll_wait_msecs, opts->socket_timeout_usecs);

  fclose(fp);

  write_replay_helper(script_path, artifact_path, opts);

  ck_free(target_cmd);
  ck_free(script_path);
  ck_free(metadata_path);
}

static void write_hang_metadata(const char *artifact_path, options_t *opts,
                                u32 hang_hash) {
  char *metadata_path = append_suffix(artifact_path, ".txt");
  char *script_path = append_suffix(artifact_path, ".replay.ps1");
  char *target_cmd = build_command_line(opts->target_argv, opts->target_argc);
  FILE *fp = fopen(metadata_path, "w");

  if (!fp) {
    ck_free(target_cmd);
    ck_free(script_path);
    ck_free(metadata_path);
    return;
  }

  fprintf(fp, "artifact          : %s\n", artifact_path);
  fprintf(fp, "hang_hash         : %08x\n", hang_hash);
  fprintf(fp, "timeout_ms        : %u\n", opts->target_shutdown_ms);
  fprintf(fp, "protocol          : %s\n", opts->protocol);
  fprintf(fp, "net_config        : %s\n", opts->net_config);
  fprintf(fp, "poll_wait_msecs   : %u\n", opts->poll_wait_msecs);
  fprintf(fp, "socket_timeout_us : %u\n", opts->socket_timeout_usecs);
  fprintf(fp, "target_cwd        : %s\n", opts->target_cwd ? opts->target_cwd : ".");
  fprintf(fp, "target_command    : %s\n", target_cmd);
  fprintf(fp, "target_env_vars   : %u\n", opts->target_env_count);
  for (int i = 0; i < (int)opts->target_env_count; i++)
    fprintf(fp, "target_env_%03d    : %s\n", i, opts->target_env[i]);
  fprintf(fp, "manual_replay     : start the target command, then run:\n");
  fprintf(fp, "manual_replay_cmd : aflnet-replay.exe \"%s\" %s %s %u %u\n",
          artifact_path, opts->protocol, opts->net_config,
          opts->poll_wait_msecs, opts->socket_timeout_usecs);
  fclose(fp);

  write_replay_helper(script_path, artifact_path, opts);

  ck_free(target_cmd);
  ck_free(script_path);
  ck_free(metadata_path);
}

static HANDLE create_target_job(void) {
  HANDLE job = CreateJobObjectA(NULL, NULL);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;

  if (!job) return NULL;

  memset(&limits, 0, sizeof(limits));
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                               &limits, sizeof(limits))) {
    CloseHandle(job);
    return NULL;
  }

  return job;
}

static target_process_t start_target(options_t *opts) {
  STARTUPINFOA si;
  target_process_t target;
  DWORD creation_flags = CREATE_NO_WINDOW | CREATE_SUSPENDED;
  char *cmd = build_command_line(opts->target_argv, opts->target_argc);
  char *app_path = NULL;
  env_snapshot_t *env_snapshots = NULL;
  u32 env_snapshot_count = 0;
  BOOL created;
  DWORD create_error = ERROR_SUCCESS;

  memset(&target, 0, sizeof(target));
  target.debug_enabled = opts->minidump;
  target.job = create_target_job();
  if (target.debug_enabled) creation_flags |= DEBUG_ONLY_THIS_PROCESS;

  if (opts->target_cwd && !is_absolute_path(opts->target_argv[0])) {
    char *candidate = join_path(opts->target_cwd, opts->target_argv[0]);
    if (file_exists(candidate)) app_path = candidate;
    else ck_free(candidate);
  } else if (file_exists(opts->target_argv[0])) {
    app_path = absolute_path(opts->target_argv[0]);
  }

  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);

  apply_target_environment(opts, &env_snapshots, &env_snapshot_count);
  created = CreateProcessA(app_path, cmd, NULL, NULL, FALSE,
                           creation_flags, NULL,
                           opts->target_cwd, &si, &target.pi);
  if (!created) create_error = GetLastError();
  restore_target_environment(env_snapshots, env_snapshot_count);

  if (!created) {
    if (target.job) CloseHandle(target.job);
    if (app_path) ck_free(app_path);
    FATAL("Unable to start target process '%s' (GetLastError=%lu)", opts->target_argv[0], create_error);
  }

  if (target.job && !AssignProcessToJobObject(target.job, target.pi.hProcess)) {
    WARNF("Unable to assign target to cleanup job (GetLastError=%lu); child processes may survive this iteration",
          GetLastError());
    CloseHandle(target.job);
    target.job = NULL;
  }

  if (ResumeThread(target.pi.hThread) == (DWORD)-1) {
    TerminateProcess(target.pi.hProcess, 1);
    CloseHandle(target.pi.hThread);
    CloseHandle(target.pi.hProcess);
    if (target.job) CloseHandle(target.job);
    if (app_path) ck_free(app_path);
    FATAL("Unable to resume target process '%s' (GetLastError=%lu)", opts->target_argv[0], GetLastError());
  }

  if (app_path) ck_free(app_path);
  ck_free(cmd);
  CloseHandle(target.pi.hThread);
  return target;
}

static int is_crash_exit_code(DWORD exit_code) {
  switch (exit_code) {
    case 0xC0000005: /* STATUS_ACCESS_VIOLATION */
    case 0xC000001D: /* STATUS_ILLEGAL_INSTRUCTION */
    case 0xC000008C: /* STATUS_ARRAY_BOUNDS_EXCEEDED */
    case 0xC000008D: /* STATUS_FLOAT_DENORMAL_OPERAND */
    case 0xC000008E: /* STATUS_FLOAT_DIVIDE_BY_ZERO */
    case 0xC000008F: /* STATUS_FLOAT_INEXACT_RESULT */
    case 0xC0000090: /* STATUS_FLOAT_INVALID_OPERATION */
    case 0xC0000091: /* STATUS_FLOAT_OVERFLOW */
    case 0xC0000092: /* STATUS_FLOAT_STACK_CHECK */
    case 0xC0000093: /* STATUS_FLOAT_UNDERFLOW */
    case 0xC0000094: /* STATUS_INTEGER_DIVIDE_BY_ZERO */
    case 0xC0000095: /* STATUS_INTEGER_OVERFLOW */
    case 0xC00000FD: /* STATUS_STACK_OVERFLOW */
    case 0xC0000409: /* STATUS_STACK_BUFFER_OVERRUN */
    case 0xC0000374: /* STATUS_HEAP_CORRUPTION */
      return 1;
    default:
      return (exit_code & 0xC0000000) == 0xC0000000;
  }
}

static int should_save_crash(options_t *opts, DWORD exit_code) {
  if (exit_code == STILL_ACTIVE) return 0;
  if (is_crash_exit_code(exit_code)) return 1;
  return opts->crash_on_exit && exit_code != 0;
}

static const char *crash_reason(options_t *opts, DWORD exit_code) {
  if (is_crash_exit_code(exit_code)) return "exception_status";
  if (opts->crash_on_exit && exit_code != 0) return "nonzero_exit";
  return "none";
}

static int write_minidump_file(HANDLE process, DWORD pid, const char *path) {
  HANDLE file;
  BOOL ok;

  if (!path || !*path) return 0;

  file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE) return 0;

  ok = MiniDumpWriteDump(process, pid, file, MiniDumpNormal, NULL, NULL, NULL);
  CloseHandle(file);

  if (!ok) {
    DeleteFileA(path);
    return 0;
  }

  return 1;
}

static void close_debug_event_handles(DEBUG_EVENT *event) {
  if (event->dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT &&
      event->u.CreateProcessInfo.hFile) {
    CloseHandle(event->u.CreateProcessInfo.hFile);
  } else if (event->dwDebugEventCode == LOAD_DLL_DEBUG_EVENT &&
             event->u.LoadDll.hFile) {
    CloseHandle(event->u.LoadDll.hFile);
  }
}

static void handle_debug_event(target_process_t *target, DEBUG_EVENT *event,
                               const char *dump_path,
                               DWORD *exception_code_ref,
                               int *dump_written_ref) {
  DWORD continue_status = DBG_CONTINUE;

  if (event->dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
    DWORD code = event->u.Exception.ExceptionRecord.ExceptionCode;
    DWORD first_chance = event->u.Exception.dwFirstChance;

    if (!first_chance && is_crash_exit_code(code)) {
      if (exception_code_ref) *exception_code_ref = code;
      if (dump_path && dump_written_ref && !*dump_written_ref) {
        *dump_written_ref = write_minidump_file(target->pi.hProcess,
                                                target->pi.dwProcessId,
                                                dump_path);
      }
    }

    if (first_chance && (code == EXCEPTION_BREAKPOINT ||
                         code == EXCEPTION_SINGLE_STEP)) {
      continue_status = DBG_CONTINUE;
    } else {
      continue_status = DBG_EXCEPTION_NOT_HANDLED;
    }
  }

  close_debug_event_handles(event);
  ContinueDebugEvent(event->dwProcessId, event->dwThreadId, continue_status);
}

static void drain_debug_events(target_process_t *target, const char *dump_path,
                               DWORD *exception_code_ref,
                               int *dump_written_ref) {
  DEBUG_EVENT event;

  if (!target->debug_enabled) return;

  while (WaitForDebugEvent(&event, 0)) {
    handle_debug_event(target, &event, dump_path, exception_code_ref,
                       dump_written_ref);
  }
}

static void wait_with_debug_events(target_process_t *target, u32 usecs,
                                   const char *dump_path,
                                   DWORD *exception_code_ref,
                                   int *dump_written_ref) {
  ULONGLONG end_ms;

  if (!target->debug_enabled) {
    aflnet_sleep_us(usecs);
    return;
  }

  end_ms = GetTickCount64() + (usecs + 999) / 1000;

  do {
    DEBUG_EVENT event;
    ULONGLONG now = GetTickCount64();
    DWORD wait_ms;

    if (now >= end_ms) break;
    wait_ms = (DWORD)MIN(end_ms - now, 10);

    if (WaitForDebugEvent(&event, wait_ms)) {
      handle_debug_event(target, &event, dump_path, exception_code_ref,
                         dump_written_ref);
    }
  } while (!stop_soon);

  drain_debug_events(target, dump_path, exception_code_ref, dump_written_ref);
}

static DWORD wait_target_process(target_process_t *target, DWORD timeout_ms,
                                 const char *dump_path,
                                 DWORD *exception_code_ref,
                                 int *dump_written_ref) {
  ULONGLONG end_ms;

  if (!target->debug_enabled) return WaitForSingleObject(target->pi.hProcess, timeout_ms);

  end_ms = GetTickCount64() + timeout_ms;

  for (;;) {
    DEBUG_EVENT event;
    DWORD process_wait = WaitForSingleObject(target->pi.hProcess, 0);
    ULONGLONG now;
    DWORD wait_ms;

    if (process_wait == WAIT_OBJECT_0) return WAIT_OBJECT_0;

    now = GetTickCount64();
    if (now >= end_ms) return WAIT_TIMEOUT;
    wait_ms = (DWORD)MIN(end_ms - now, 10);

    if (WaitForDebugEvent(&event, wait_ms)) {
      handle_debug_event(target, &event, dump_path, exception_code_ref,
                         dump_written_ref);
    }
  }
}

static int request_region_bounds(region_t *regions, u32 region_count,
                                 u32 index, u32 len,
                                 u32 *start_ref, u32 *size_ref) {
  region_t *region;
  int start;
  int end;
  u32 start_u;
  u32 end_u;

  if (!regions || !len || index >= region_count) return 0;

  region = &regions[index];
  start = region->start_byte;
  end = region->end_byte;

  if (start < 0 || end < start) return 0;

  start_u = (u32)start;
  end_u = (u32)end;
  if (start_u >= len || end_u >= len) return 0;

  *start_ref = start_u;
  *size_ref = end_u - start_u + 1;
  return *size_ref != 0;
}

static void mutate(options_t *opts, u8 *buf, u32 len, region_t *regions,
                   u32 region_count, u32 mutations) {
  u32 i;

  if (!len) return;

  for (i = 0; i < mutations; i++) {
    u32 pos;
    u32 start = 0;
    u32 region_len = len;
    u8 op = rand() % (opts->dict_token_count ? 5 : 4);

    if (region_count)
      request_region_bounds(regions, region_count, rand() % region_count,
                            len, &start, &region_len);

    if (op == 4) {
      dict_token_t *token = &opts->dict_tokens[rand() % opts->dict_token_count];
      u32 copy_len = MIN(token->len, region_len);

      if (!copy_len) continue;

      pos = start + (rand() % (region_len - copy_len + 1));
      memcpy(buf + pos, token->data, copy_len);
    } else {
      pos = start + (rand() % region_len);

      switch (op) {
        case 0:
          buf[pos] ^= (u8)(1U << (rand() & 7));
          break;
        case 1:
          buf[pos] = (u8)rand();
          break;
        case 2:
          buf[pos]++;
          break;
        default:
          buf[pos]--;
          break;
      }
    }
  }
}

static void save_replay_file(const char *path, u8 *buf, u32 len,
                             region_t *regions, u32 region_count) {
  FILE *fp = fopen(path, "wb");
  u32 i;

  if (!fp) PFATAL("Unable to create replay file '%s'", path);

  for (i = 0; i < region_count; i++) {
    u32 start;
    u32 size;

    if (!request_region_bounds(regions, region_count, i, len, &start, &size))
      continue;

    if (fwrite(&size, sizeof(size), 1, fp) != 1 ||
        fwrite(buf + start, 1, size, fp) != size) {
      PFATAL("Short write to replay file '%s'", path);
    }
  }

  fclose(fp);
}

static int send_sequence(options_t *opts, u8 *buf, u32 len,
                         region_t *regions, u32 region_count,
                         char **response_buf_ref, unsigned int *response_len_ref) {
  aflnet_socket_t sockfd = AFLNET_INVALID_SOCKET;
  struct timeval timeout;
  u32 i;
  int n;

  timeout.tv_sec = 0;
  timeout.tv_usec = opts->socket_timeout_usecs;

  if (aflnet_connect(&sockfd, opts->net_protocol, (char *)opts->net_ip,
                     opts->net_port, timeout))
    return 1;

  if (net_recv(sockfd, timeout, opts->poll_wait_msecs, response_buf_ref, response_len_ref)) {
    aflnet_close_socket(sockfd);
    return 1;
  }

  for (i = 0; i < region_count; i++) {
    u32 start;
    u32 size;

    if (!request_region_bounds(regions, region_count, i, len, &start, &size))
      continue;

    n = net_send(sockfd, timeout, (char *)(buf + start), size);
    if (n != (int)size) {
      aflnet_close_socket(sockfd);
      return 1;
    }

    if (net_recv(sockfd, timeout, opts->poll_wait_msecs, response_buf_ref, response_len_ref)) {
      aflnet_close_socket(sockfd);
      return 1;
    }
  }

  net_recv(sockfd, timeout, opts->poll_wait_msecs, response_buf_ref, response_len_ref);
  aflnet_close_socket(sockfd);
  return 0;
}

static int note_unique_state(run_state_t *state, u32 hash) {
  u32 i;

  for (i = 0; i < state->state_hash_count; i++)
    if (state->state_hashes[i] == hash) return 0;

  state->state_hashes = (u32 *)ck_realloc(state->state_hashes,
                                          (state->state_hash_count + 1) * sizeof(u32));
  state->state_hashes[state->state_hash_count++] = hash;
  return 1;
}

static int note_unique_coverage(run_state_t *state, u32 hash) {
  u32 i;

  for (i = 0; i < state->coverage_hash_count; i++)
    if (state->coverage_hashes[i] == hash) return 0;

  state->coverage_hashes = (u32 *)ck_realloc(state->coverage_hashes,
                                             (state->coverage_hash_count + 1) * sizeof(u32));
  state->coverage_hashes[state->coverage_hash_count++] = hash;
  return 1;
}

static int note_unique_crash(run_state_t *state, u32 hash) {
  u32 i;

  for (i = 0; i < state->crash_hash_count; i++)
    if (state->crash_hashes[i] == hash) return 0;

  state->crash_hashes = (u32 *)ck_realloc(state->crash_hashes,
                                          (state->crash_hash_count + 1) * sizeof(u32));
  state->crash_hashes[state->crash_hash_count++] = hash;
  return 1;
}

static int note_unique_hang(run_state_t *state, u32 hash) {
  u32 i;

  for (i = 0; i < state->hang_hash_count; i++)
    if (state->hang_hashes[i] == hash) return 0;

  state->hang_hashes = (u32 *)ck_realloc(state->hang_hashes,
                                         (state->hang_hash_count + 1) * sizeof(u32));
  state->hang_hashes[state->hang_hash_count++] = hash;
  return 1;
}

static u32 hash_state_sequence(unsigned int *state_sequence, unsigned int state_count) {
  u32 hash = 2166136261U;
  unsigned int i;

  for (i = 0; i < state_count; i++) {
    hash ^= state_sequence[i];
    hash *= 16777619U;
  }

  return hash;
}

static u32 hash_bytes(u8 *buf, u32 len) {
  u32 hash = 2166136261U;
  u32 i;

  for (i = 0; i < len; i++) {
    hash ^= buf[i];
    hash *= 16777619U;
  }

  return hash;
}

static u32 hash_crash(u8 *buf, u32 len, DWORD exit_code) {
  u32 hash = hash_bytes(buf, len);
  u32 i;

  for (i = 0; i < sizeof(exit_code); i++) {
    hash ^= (u8)((exit_code >> (i * 8)) & 0xff);
    hash *= 16777619U;
  }

  return hash;
}

static u32 hash_hang(u8 *buf, u32 len, u32 timeout_ms) {
  u32 hash = hash_bytes(buf, len);
  u32 i;

  hash ^= 0x48414e47U; /* HANG */
  hash *= 16777619U;

  for (i = 0; i < sizeof(timeout_ms); i++) {
    hash ^= (u8)((timeout_ms >> (i * 8)) & 0xff);
    hash *= 16777619U;
  }

  return hash;
}

static int is_safe_filename_component_char(unsigned char ch) {
  if (ch <= 31 || ch >= 127) return 0;

  switch (ch) {
    case '<':
    case '>':
    case ':':
    case '"':
    case '/':
    case '\\':
    case '|':
    case '?':
    case '*':
      return 0;
    default:
      return 1;
  }
}

static char *sanitize_filename_component(const char *value) {
  enum { COMPONENT_LIMIT = 96, HASH_SUFFIX_LEN = 10 };
  const char *source = (value && value[0]) ? value : "none";
  u32 source_len = (u32)strlen(source);
  u32 hash = hash_bytes((u8 *)source, source_len);
  char *out = (char *)ck_alloc(COMPONENT_LIMIT + HASH_SUFFIX_LEN + 1);
  u32 out_len = 0;
  u32 i;
  int truncated = 0;

  for (i = 0; i < source_len; i++) {
    unsigned char ch = (unsigned char)source[i];

    if (out_len >= COMPONENT_LIMIT) {
      truncated = 1;
      break;
    }

    out[out_len++] = is_safe_filename_component_char(ch) ? (char)ch : '_';
  }

  while (out_len && (out[out_len - 1] == '.' || out[out_len - 1] == ' '))
    out[out_len - 1] = '_';

  if (!out_len) {
    memcpy(out, "none", 5);
    return out;
  }

  if (truncated || i < source_len) {
    while (out_len > COMPONENT_LIMIT - HASH_SUFFIX_LEN) out_len--;
    while (out_len && (out[out_len - 1] == '.' || out[out_len - 1] == ' '))
      out[out_len - 1] = '_';
    snprintf(out + out_len, HASH_SUFFIX_LEN + 1, "_h%08x", hash);
  } else {
    out[out_len] = '\0';
  }

  return out;
}

static void write_discovery_metadata(const char *artifact_path,
                                     const char *kind,
                                     seed_t *seed,
                                     const char *queue_path,
                                     u32 hash,
                                     const char *detail,
                                     u32 signal_len) {
  char *metadata_path = append_suffix(artifact_path, ".txt");
  FILE *fp = fopen(metadata_path, "w");

  if (!fp) {
    ck_free(metadata_path);
    return;
  }

  fprintf(fp, "artifact          : %s\n", artifact_path);
  fprintf(fp, "kind              : %s\n", kind);
  fprintf(fp, "source_seed       : %s\n", seed->path);
  fprintf(fp, "source_size       : %u\n", seed->len);
  fprintf(fp, "queue_entry       : %s\n", queue_path);
  fprintf(fp, "signal_hash       : %08x\n", hash);
  fprintf(fp, "signal_len        : %u\n", signal_len);
  if (detail) fprintf(fp, "signal_detail     : %s\n", detail);

  fclose(fp);
  ck_free(metadata_path);
}

static int save_interesting_state(run_state_t *state, seed_t *seed, u8 *buf,
                                  unsigned int *state_sequence,
                                  unsigned int state_count,
                                  char **queue_path_ref) {
  u32 hash;
  u8 *state_str;
  const char *state_detail;
  char *state_name;
  char *path;
  char *queue_path;

  if (queue_path_ref) *queue_path_ref = NULL;
  if (!state_count) return 0;

  hash = hash_state_sequence(state_sequence, state_count);
  if (!note_unique_state(state, hash)) return 0;

  state_str = state_sequence_to_string(state_sequence, state_count);
  state_detail = (char *)(state_str ? state_str : (u8 *)"none");
  state_name = sanitize_filename_component(state_detail);
  path = alloc_printf("%s\\id_%06u,state_%s", state->states_dir,
                      state->unique_states, state_name);
  queue_path = alloc_printf("%s\\id_%06u,state_%s.raw", state->queue_dir,
                            state->queued_paths, state_name);

  save_replay_file(path, buf, seed->len, seed->regions, seed->region_count);
  save_raw_file(queue_path, buf, seed->len);
  write_discovery_metadata(path, "state", seed, queue_path, hash,
                           state_detail, state_count);
  append_queue_manifest(state, "state", queue_path, seed, hash,
                        state_detail);
  append_hash_index(state->state_index_path, hash);
  state->unique_states++;
  state->queued_paths++;

  ck_free(state_name);
  if (state_str) ck_free(state_str);
  if (queue_path_ref) *queue_path_ref = queue_path;
  else ck_free(queue_path);
  ck_free(path);
  return 1;
}

static u32 save_interesting_coverage(run_state_t *state, seed_t *seed, u8 *buf,
                                     u8 *coverage_buf, u32 coverage_len,
                                     char **queue_path_ref) {
  u32 hash;
  u32 new_bits;
  char *path;
  char *queue_path;
  char *detail;

  if (queue_path_ref) *queue_path_ref = NULL;
  if (!coverage_len) return 0;

  new_bits = note_new_coverage_bits(state, coverage_buf, coverage_len);
  if (!new_bits) return 0;

  hash = hash_bytes(coverage_buf, coverage_len);
  if (!note_unique_coverage(state, hash)) return new_bits;

  detail = alloc_printf("new_bits=%u", new_bits);
  path = alloc_printf("%s\\id_%06u,cov_%08x", state->coverage_dir,
                      state->unique_coverage, hash);
  queue_path = alloc_printf("%s\\id_%06u,cov_%08x.raw", state->queue_dir,
                            state->queued_paths, hash);

  save_replay_file(path, buf, seed->len, seed->regions, seed->region_count);
  save_raw_file(queue_path, buf, seed->len);
  write_discovery_metadata(path, "coverage", seed, queue_path, hash, detail,
                           coverage_len);
  append_queue_manifest(state, "coverage", queue_path, seed, hash, detail);
  append_hash_index(state->coverage_index_path, hash);
  state->unique_coverage++;
  state->queued_paths++;

  ck_free(detail);
  if (queue_path_ref) *queue_path_ref = queue_path;
  else ck_free(queue_path);
  ck_free(path);
  return new_bits;
}

static u32 count_coverage_seen(run_state_t *state) {
  u32 i;
  u32 count = 0;

  for (i = 0; i < state->coverage_seen_len; i++)
    if (state->coverage_seen[i]) count++;

  return count;
}

static void write_stats(options_t *opts, run_state_t *state) {
  FILE *fp = fopen(state->stats_path, "w");
  time_t now = time(NULL);
  char *target_cmd = NULL;
  u32 i;

  if (!fp) return;
  if (!opts->no_launch) target_cmd = build_command_line(opts->target_argv, opts->target_argc);

  fprintf(fp, "start_time        : %lld\n", (long long)state->start_time);
  fprintf(fp, "last_update       : %lld\n", (long long)now);
  fprintf(fp, "run_time          : %lld\n", (long long)(now - state->start_time));
  fprintf(fp, "execs_done        : %u\n", state->total_execs);
  fprintf(fp, "active_seeds      : %u\n", state->active_seeds);
  fprintf(fp, "queued_paths      : %u\n", state->queued_paths);
  fprintf(fp, "unique_states     : %u\n", state->unique_states);
  fprintf(fp, "unique_coverage   : %u\n", state->unique_coverage);
  fprintf(fp, "coverage_bits_seen: %u\n", count_coverage_seen(state));
  fprintf(fp, "coverage_map_bytes: %u\n", state->coverage_seen_len);
  fprintf(fp, "saved_crashes     : %u\n", state->saved_crashes);
  fprintf(fp, "saved_hangs       : %u\n", state->saved_hangs);
  fprintf(fp, "saved_net_errors  : %u\n", state->saved_net_errors);
  fprintf(fp, "protocol          : %s\n", opts->protocol);
  fprintf(fp, "net_config        : %s\n", opts->net_config);
  fprintf(fp, "coverage_map      : %s\n", opts->coverage_map ? opts->coverage_map : "none");
  fprintf(fp, "exec_log          : %s\n", state->exec_log_path);
  fprintf(fp, "target_path       : %s\n", opts->no_launch ? "external" : opts->target_argv[0]);
  fprintf(fp, "target_command    : %s\n", opts->no_launch ? "external" : (target_cmd ? target_cmd : ""));
  fprintf(fp, "target_cwd        : %s\n", opts->no_launch ? "external" : (opts->target_cwd ? opts->target_cwd : "."));
  fprintf(fp, "dictionary        : %s\n", opts->dictionary_path ? opts->dictionary_path : "none");
  fprintf(fp, "dictionary_tokens : %u\n", opts->dict_token_count);
  fprintf(fp, "target_env_vars   : %u\n", opts->target_env_count);
  for (i = 0; i < opts->target_env_count; i++)
    fprintf(fp, "target_env_%03u    : %s\n", i, opts->target_env[i]);
  fprintf(fp, "dry_run           : %u\n", opts->dry_run);
  fprintf(fp, "no_launch         : %u\n", opts->no_launch);
  fprintf(fp, "minidump          : %u\n", opts->minidump);
  fprintf(fp, "crash_on_exit     : %u\n", opts->crash_on_exit);
  fprintf(fp, "rng_seed          : %u\n", opts->rng_seed);
  fprintf(fp, "mutations_per_exec: %u\n", opts->mutations_per_exec);
  fprintf(fp, "iteration_limit   : %u\n", opts->iterations);
  fprintf(fp, "time_limit_secs   : %u\n", opts->max_run_seconds);
  fprintf(fp, "stop_reason       : %s\n", state->stop_reason ? state->stop_reason : "running");

  fclose(fp);
  if (target_cmd) ck_free(target_cmd);
}

static void fuzz_one(options_t *opts, run_state_t *state, seed_t **seeds_ref,
                     u32 *seed_count_ref, seed_t *seed) {
  target_process_t target;
  DWORD wait_result = WAIT_TIMEOUT;
  DWORD exit_code = STILL_ACTIVE;
  region_t *seed_regions = seed->regions;
  u32 seed_region_count = seed->region_count;
  u32 seed_len = seed->len;
  u8 *mutated = (u8 *)ck_alloc(seed_len);
  char *response_buf = NULL;
  unsigned int response_len = 0;
  unsigned int response_state_count = 0;
  unsigned int *response_states = NULL;
  u8 *coverage_buf = NULL;
  u32 coverage_len = 0;
  u32 coverage_new_bits = 0;
  int send_failed;
  int target_timed_out = 0;
  const char *outcome = "ok";
  const char *crash_reason_text = "none";
  DWORD target_pid = 0;
  char *state_queue_path = NULL;
  char *coverage_queue_path = NULL;
  char *debug_dump_path = NULL;
  DWORD debug_exception_code = 0;
  int debug_dump_written = 0;

  memset(&target, 0, sizeof(target));
  memcpy(mutated, seed->data, seed_len);
  if (opts->dry_run) {
    outcome = "dry_run";
  } else {
    mutate(opts, mutated, seed_len, seed_regions, seed_region_count,
           opts->mutations_per_exec);
  }

  if (opts->coverage_map && !opts->no_launch) DeleteFileA(opts->coverage_map);
  if (opts->minidump && !opts->no_launch) {
    debug_dump_path = alloc_printf("%s\\debug_%06u.dmp.tmp",
                                   state->crashes_dir, state->total_execs);
    DeleteFileA(debug_dump_path);
  }

  if (!opts->no_launch) {
    target = start_target(opts);
    target_pid = target.pi.dwProcessId;
    wait_with_debug_events(&target, opts->server_wait_usecs, debug_dump_path,
                           &debug_exception_code, &debug_dump_written);
  } else {
    exit_code = 0;
  }

  send_failed = send_sequence(opts, mutated, seed_len,
                              seed_regions, seed_region_count,
                              &response_buf, &response_len);

  if (!opts->no_launch) {
    wait_result = wait_target_process(&target, opts->target_shutdown_ms,
                                      debug_dump_path, &debug_exception_code,
                                      &debug_dump_written);
    if (wait_result == WAIT_OBJECT_0) {
      GetExitCodeProcess(target.pi.hProcess, &exit_code);
      if (debug_exception_code && !is_crash_exit_code(exit_code))
        exit_code = debug_exception_code;
    } else if (debug_exception_code) {
      exit_code = debug_exception_code;
      if (wait_target_process(&target, 1000, NULL, NULL, NULL) != WAIT_OBJECT_0)
        TerminateProcess(target.pi.hProcess, exit_code);
    } else {
      target_timed_out = 1;
      TerminateProcess(target.pi.hProcess, 0);
      wait_target_process(&target, 1000, NULL, NULL, NULL);
    }
  }

  if (response_len) {
    response_states = (*extract_response_codes)((unsigned char *)response_buf,
                                                response_len, &response_state_count);
    save_interesting_state(state, seed, mutated, response_states,
                           response_state_count,
                           opts->dry_run ? NULL : &state_queue_path);
  }

  if (opts->coverage_map && read_optional_file(opts->coverage_map, &coverage_buf, &coverage_len))
    coverage_new_bits = save_interesting_coverage(state, seed, mutated,
                                                  coverage_buf, coverage_len,
                                                  opts->dry_run ? NULL :
                                                  &coverage_queue_path);

  if (!opts->no_launch && should_save_crash(opts, exit_code)) {
    u32 crash_hash = hash_crash(mutated, seed_len, exit_code);
    const char *reason = crash_reason(opts, exit_code);

    outcome = "crash";
    crash_reason_text = reason;
    if (note_unique_crash(state, crash_hash)) {
      char *path = alloc_printf("%s\\id_%06u,exit_%08lx,hash_%08x",
                                state->crashes_dir, state->saved_crashes,
                                (unsigned long)exit_code, crash_hash);
      char *dump_path = NULL;
      save_replay_file(path, mutated, seed_len, seed_regions, seed_region_count);
      if (debug_dump_written && debug_dump_path && file_exists(debug_dump_path)) {
        dump_path = append_suffix(path, ".dmp");
        if (!MoveFileExA(debug_dump_path, dump_path, MOVEFILE_REPLACE_EXISTING)) {
          WARNF("Unable to move crash minidump to '%s' (GetLastError=%lu)",
                dump_path, GetLastError());
          DeleteFileA(debug_dump_path);
          ck_free(dump_path);
          dump_path = NULL;
        }
      }
      write_replay_metadata(path, opts, exit_code, crash_hash, dump_path, reason);
      append_hash_index(state->crash_index_path, crash_hash);
      state->saved_crashes++;
      if (dump_path) ck_free(dump_path);
      ck_free(path);
    }
  } else if (!opts->no_launch && target_timed_out && !send_failed && !response_len) {
    u32 hang_hash = hash_hang(mutated, seed_len, opts->target_shutdown_ms);

    outcome = "hang";
    if (note_unique_hang(state, hang_hash)) {
      char *path = alloc_printf("%s\\id_%06u,hang_%08x",
                                state->hangs_dir, state->saved_hangs,
                                hang_hash);
      save_replay_file(path, mutated, seed_len, seed_regions, seed_region_count);
      write_hang_metadata(path, opts, hang_hash);
      append_hash_index(state->hang_index_path, hang_hash);
      state->saved_hangs++;
      ck_free(path);
    }
  } else if (send_failed && state->saved_net_errors < 16) {
    char *path = alloc_printf("%s\\id_%06u,send_failed", state->net_errors_dir,
                              state->saved_net_errors);
    outcome = "net_error";
    save_replay_file(path, mutated, seed_len, seed_regions, seed_region_count);
    state->saved_net_errors++;
    ck_free(path);
  } else if (send_failed) {
    outcome = "net_error";
  } else if (!response_len) {
    outcome = "no_response";
  }

  append_exec_log(state, seed, outcome, response_len, response_state_count,
                  coverage_len, coverage_new_bits, exit_code, target_pid,
                  send_failed, target_timed_out, crash_reason_text);

  if (!opts->dry_run) {
    if (state_queue_path) {
      append_active_seed(state, seeds_ref, seed_count_ref, state_queue_path,
                         mutated, seed_len, seed_regions, seed_region_count);
      state_queue_path = NULL;
    }

    if (coverage_queue_path) {
      append_active_seed(state, seeds_ref, seed_count_ref, coverage_queue_path,
                         mutated, seed_len, seed_regions, seed_region_count);
      coverage_queue_path = NULL;
    }
  }

  if (!opts->no_launch) {
    if (target.pi.hProcess) CloseHandle(target.pi.hProcess);
    if (target.job) CloseHandle(target.job);
  }
  if (debug_dump_path) {
    DeleteFileA(debug_dump_path);
    ck_free(debug_dump_path);
  }
  if (state_queue_path) ck_free(state_queue_path);
  if (coverage_queue_path) ck_free(coverage_queue_path);
  if (coverage_buf) ck_free(coverage_buf);
  if (response_states) ck_free(response_states);
  if (response_buf) ck_free(response_buf);
  ck_free(mutated);
  state->total_execs++;
}

static void parse_args(int argc, char **argv, options_t *opts) {
  int i;

  memset(opts, 0, sizeof(*opts));
  opts->server_wait_usecs = 10000;
  opts->poll_wait_msecs = 1;
  opts->socket_timeout_usecs = 1000;
  opts->target_shutdown_ms = 250;
  opts->iterations = 1000;
  opts->mutations_per_exec = 8;

  for (i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--")) {
      i++;
      break;
    } else if (!strcmp(argv[i], "-i") && i + 1 < argc) {
      opts->in_dir = argv[++i];
    } else if (!strcmp(argv[i], "-o") && i + 1 < argc) {
      opts->out_dir = argv[++i];
    } else if (!strcmp(argv[i], "-N") && i + 1 < argc) {
      opts->net_config = argv[++i];
    } else if (!strcmp(argv[i], "-P") && i + 1 < argc) {
      opts->protocol = argv[++i];
    } else if (!strcmp(argv[i], "-D") && i + 1 < argc) {
      opts->server_wait_usecs = parse_u32_option(argv[++i], "-D");
    } else if (!strcmp(argv[i], "-W") && i + 1 < argc) {
      opts->poll_wait_msecs = parse_u32_option(argv[++i], "-W");
    } else if (!strcmp(argv[i], "-w") && i + 1 < argc) {
      opts->socket_timeout_usecs = parse_u32_option(argv[++i], "-w");
    } else if (!strcmp(argv[i], "-B") && i + 1 < argc) {
      opts->coverage_map = argv[++i];
    } else if (!strcmp(argv[i], "-C") && i + 1 < argc) {
      opts->target_cwd = argv[++i];
    } else if (!strcmp(argv[i], "-E") && i + 1 < argc) {
      char *assignment = argv[++i];

      env_assignment_value(assignment);
      opts->target_env = (char **)ck_realloc(
          opts->target_env, (opts->target_env_count + 1) * sizeof(char *));
      opts->target_env[opts->target_env_count++] = assignment;
    } else if (!strcmp(argv[i], "-X") && i + 1 < argc) {
      opts->dictionary_path = argv[++i];
    } else if (!strcmp(argv[i], "-t") && i + 1 < argc) {
      opts->target_shutdown_ms = parse_u32_option(argv[++i], "-t");
    } else if (!strcmp(argv[i], "-x") && i + 1 < argc) {
      opts->iterations = parse_u32_option(argv[++i], "-x");
    } else if (!strcmp(argv[i], "-V") && i + 1 < argc) {
      opts->max_run_seconds = parse_u32_option(argv[++i], "-V");
    } else if (!strcmp(argv[i], "-m") && i + 1 < argc) {
      opts->mutations_per_exec = parse_u32_option(argv[++i], "-m");
    } else if (!strcmp(argv[i], "-Z")) {
      opts->dry_run = 1;
    } else if (!strcmp(argv[i], "-S") && i + 1 < argc) {
      opts->rng_seed = parse_u32_option(argv[++i], "-S");
      opts->rng_seed_given = 1;
    } else if (!strcmp(argv[i], "--no-launch")) {
      opts->no_launch = 1;
    } else if (!strcmp(argv[i], "--minidump")) {
      opts->minidump = 1;
    } else if (!strcmp(argv[i], "--crash-on-exit")) {
      opts->crash_on_exit = 1;
    } else {
      usage(argv[0]);
    }
  }

  if (!opts->in_dir || !opts->out_dir || !opts->protocol || !opts->net_config)
    usage(argv[0]);

  if (opts->no_launch) {
    if (opts->minidump) FATAL("--minidump requires the fuzzer to launch the target process");
    if (opts->crash_on_exit) FATAL("--crash-on-exit requires the fuzzer to launch the target process");
    if (opts->target_env_count) FATAL("-E requires the fuzzer to launch the target process");
    if (i < argc) FATAL("Do not pass a target command with --no-launch");
    opts->target_argv = NULL;
    opts->target_argc = 0;
  } else {
    if (i >= argc) usage(argv[0]);
    opts->target_argv = &argv[i];
    opts->target_argc = argc - i;
  }
}

int main(int argc, char **argv) {
  options_t opts;
  run_state_t state;
  seed_t *seeds = NULL;
  u32 seed_count = 0;
  u32 i = 0;

  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
  SetConsoleCtrlHandler(handle_console_event, TRUE);

  parse_args(argc, argv, &opts);

  if (opts.coverage_map) opts.coverage_map = absolute_path(opts.coverage_map);
  if (!opts.no_launch && opts.target_cwd) opts.target_cwd = absolute_path(opts.target_cwd);
  if (opts.dictionary_path) opts.dictionary_path = absolute_path(opts.dictionary_path);

  if (aflnet_select_protocol(opts.protocol, &extract_requests, &extract_response_codes))
    FATAL("%s protocol is not supported yet", opts.protocol);
  init_message_code_map();

  if (!opts.no_launch && opts.target_cwd && !dir_exists(opts.target_cwd))
    FATAL("Target working directory '%s' does not exist", opts.target_cwd);

  if (parse_net_config((u8 *)opts.net_config, &opts.net_protocol, &opts.net_ip, &opts.net_port))
    FATAL("Bad syntax used for -N. Expected [tcp/udp]://127.0.0.1/port");

  load_dictionary(&opts);

  memset(&state, 0, sizeof(state));
  state.start_time = time(NULL);
  state.stop_reason = "running";
  ensure_dir(opts.out_dir);
  state.queue_dir = join_path(opts.out_dir, "queue");
  state.states_dir = join_path(opts.out_dir, "states");
  state.coverage_dir = join_path(opts.out_dir, "coverage");
  state.crashes_dir = join_path(opts.out_dir, "replayable-crashes");
  state.hangs_dir = join_path(opts.out_dir, "hangs");
  state.net_errors_dir = join_path(opts.out_dir, "network-errors");
  state.stats_path = join_path(opts.out_dir, "fuzzer_stats");
  state.state_index_path = join_path(opts.out_dir, "state_hashes.txt");
  state.coverage_index_path = join_path(opts.out_dir, "coverage_hashes.txt");
  state.crash_index_path = join_path(opts.out_dir, "crash_hashes.txt");
  state.hang_index_path = join_path(opts.out_dir, "hang_hashes.txt");
  state.coverage_bits_path = join_path(opts.out_dir, "coverage_bits.bin");
  state.queue_manifest_path = join_path(opts.out_dir, "queue_manifest.tsv");
  state.exec_log_path = join_path(opts.out_dir, "exec_log.tsv");
  ensure_queue_manifest_header(&state);
  ensure_exec_log_header(&state);
  ensure_dir(state.queue_dir);
  ensure_dir(state.states_dir);
  if (opts.coverage_map) ensure_dir(state.coverage_dir);
  ensure_dir(state.crashes_dir);
  ensure_dir(state.hangs_dir);
  ensure_dir(state.net_errors_dir);
  state.queued_paths = count_files_in_dir(state.queue_dir);
  state.unique_states = count_files_in_dir(state.states_dir);
  state.unique_coverage = opts.coverage_map ? count_files_in_dir(state.coverage_dir) : 0;
  state.saved_crashes = count_files_in_dir(state.crashes_dir);
  state.saved_hangs = count_files_in_dir(state.hangs_dir);
  state.saved_net_errors = count_files_in_dir(state.net_errors_dir);
  load_hash_index(state.state_index_path, &state.state_hashes, &state.state_hash_count);
  load_hash_index(state.coverage_index_path, &state.coverage_hashes, &state.coverage_hash_count);
  load_hash_index(state.crash_index_path, &state.crash_hashes, &state.crash_hash_count);
  load_hash_index(state.hang_index_path, &state.hang_hashes, &state.hang_hash_count);
  if (opts.coverage_map) load_coverage_bits(&state);

  if (!opts.rng_seed_given) opts.rng_seed = (u32)time(NULL);
  srand(opts.rng_seed);
  load_seeds(&opts, &state, &seeds, &seed_count);
  write_stats(&opts, &state);

  ACTF("Loaded %u seeds. Starting native Windows %s%s.", seed_count,
       opts.dry_run ? "dry run" : "state fuzzing",
       opts.no_launch ? " against an already-running target" : "");

  if (opts.dry_run) {
    for (i = 0; !stop_soon && i < seed_count; i++) {
      fuzz_one(&opts, &state, &seeds, &seed_count, &seeds[i]);
    }

    if (!stop_soon) state.stop_reason = "dry_run";
  } else {
    while (!stop_soon && (!opts.iterations || i < opts.iterations)) {
      u32 seed_index = rand() % seed_count;
      seed_t *seed = &seeds[seed_index];
      fuzz_one(&opts, &state, &seeds, &seed_count, seed);
      i++;

      if (opts.max_run_seconds &&
          (u32)(time(NULL) - state.start_time) >= opts.max_run_seconds) {
        state.stop_reason = "time_limit";
        break;
      }

      if (i % 100 == 0) {
        OKF("execs=%u active_seeds=%u unique_states=%u unique_coverage=%u crashes=%u hangs=%u net_errors=%u",
            state.total_execs, state.active_seeds, state.unique_states, state.unique_coverage,
            state.saved_crashes, state.saved_hangs, state.saved_net_errors);
        write_stats(&opts, &state);
      }
    }
  }

  if (stop_soon) state.stop_reason = "signal";
  else if (!opts.dry_run && opts.iterations && i >= opts.iterations) state.stop_reason = "iteration_limit";

  write_stats(&opts, &state);
  OKF("Done. execs=%u active_seeds=%u unique_states=%u unique_coverage=%u crashes=%u hangs=%u net_errors=%u",
      state.total_execs, state.active_seeds, state.unique_states, state.unique_coverage,
      state.saved_crashes, state.saved_hangs, state.saved_net_errors);

  destroy_message_code_map();
  return 0;
}

#endif /* _WIN32 */
