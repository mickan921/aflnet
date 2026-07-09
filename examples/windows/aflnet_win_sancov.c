/*
   AFLNet Windows SanitizerCoverage bitmap writer.

   Link this file into a Windows target compiled with clang
   -fsanitize-coverage=trace-pc-guard. At runtime, set AFLNET_COVERAGE_FILE
   to the raw bitmap path. aflnet-win-fuzz.exe does that automatically when
   launched with -B.
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>

#  ifndef AFLNET_WIN_COVERAGE_MAP_SIZE
#    define AFLNET_WIN_COVERAGE_MAP_SIZE 65536U
#  endif

static unsigned char aflnet_cov_map[AFLNET_WIN_COVERAGE_MAP_SIZE];
static unsigned char *aflnet_cov_live_map = aflnet_cov_map;
static HANDLE aflnet_cov_file = INVALID_HANDLE_VALUE;
static HANDLE aflnet_cov_mapping = NULL;
static volatile LONG aflnet_cov_initialized;
static uint32_t aflnet_next_guard = 1;

static void aflnet_map_coverage_file(void) {
  const char *path = getenv("AFLNET_COVERAGE_FILE");
  LARGE_INTEGER size;

  if (!path || !*path) return;

  aflnet_cov_file = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (aflnet_cov_file == INVALID_HANDLE_VALUE) return;

  size.QuadPart = AFLNET_WIN_COVERAGE_MAP_SIZE;
  if (!SetFilePointerEx(aflnet_cov_file, size, NULL, FILE_BEGIN) ||
      !SetEndOfFile(aflnet_cov_file)) {
    CloseHandle(aflnet_cov_file);
    aflnet_cov_file = INVALID_HANDLE_VALUE;
    return;
  }

  aflnet_cov_mapping = CreateFileMappingA(aflnet_cov_file, NULL, PAGE_READWRITE,
                                          0, AFLNET_WIN_COVERAGE_MAP_SIZE, NULL);
  if (!aflnet_cov_mapping) {
    CloseHandle(aflnet_cov_file);
    aflnet_cov_file = INVALID_HANDLE_VALUE;
    return;
  }

  aflnet_cov_live_map = (unsigned char *)MapViewOfFile(
      aflnet_cov_mapping, FILE_MAP_ALL_ACCESS, 0, 0, AFLNET_WIN_COVERAGE_MAP_SIZE);
  if (!aflnet_cov_live_map) {
    CloseHandle(aflnet_cov_mapping);
    CloseHandle(aflnet_cov_file);
    aflnet_cov_mapping = NULL;
    aflnet_cov_file = INVALID_HANDLE_VALUE;
    aflnet_cov_live_map = aflnet_cov_map;
    return;
  }

  memset(aflnet_cov_live_map, 0, AFLNET_WIN_COVERAGE_MAP_SIZE);
}

static void aflnet_write_coverage(void) {
  const char *path;
  FILE *fp;

  if (aflnet_cov_live_map != aflnet_cov_map) {
    FlushViewOfFile(aflnet_cov_live_map, AFLNET_WIN_COVERAGE_MAP_SIZE);
    return;
  }

  path = getenv("AFLNET_COVERAGE_FILE");
  if (!path || !*path) return;

  fp = fopen(path, "wb");
  if (!fp) return;
  fwrite(aflnet_cov_live_map, 1, AFLNET_WIN_COVERAGE_MAP_SIZE, fp);
  fclose(fp);
}

static void aflnet_cov_runtime_shutdown(void) {
  aflnet_write_coverage();

  if (aflnet_cov_live_map != aflnet_cov_map) {
    UnmapViewOfFile(aflnet_cov_live_map);
    aflnet_cov_live_map = aflnet_cov_map;
  }

  if (aflnet_cov_mapping) {
    CloseHandle(aflnet_cov_mapping);
    aflnet_cov_mapping = NULL;
  }

  if (aflnet_cov_file != INVALID_HANDLE_VALUE) {
    CloseHandle(aflnet_cov_file);
    aflnet_cov_file = INVALID_HANDLE_VALUE;
  }
}

static LONG WINAPI aflnet_unhandled_exception_filter(EXCEPTION_POINTERS *info) {
  (void)info;
  aflnet_write_coverage();
  return EXCEPTION_CONTINUE_SEARCH;
}

static void aflnet_cov_runtime_init(void) {
  if (InterlockedCompareExchange(&aflnet_cov_initialized, 1, 0) != 0) return;

  memset(aflnet_cov_map, 0, sizeof(aflnet_cov_map));
  aflnet_map_coverage_file();
  atexit(aflnet_cov_runtime_shutdown);
  SetUnhandledExceptionFilter(aflnet_unhandled_exception_filter);
}

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
  if (start == stop || *start) return;

  aflnet_cov_runtime_init();

  while (start < stop) {
    *start = aflnet_next_guard++;
    if (!aflnet_next_guard) aflnet_next_guard = 1;
    start++;
  }
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
  uint32_t id = *guard;

  if (!id) return;
  aflnet_cov_live_map[id % AFLNET_WIN_COVERAGE_MAP_SIZE]++;
}

__declspec(dllexport) void aflnet_windows_coverage_dump(void) {
  aflnet_write_coverage();
}

__declspec(dllexport) void aflnet_windows_coverage_reset(void) {
  memset(aflnet_cov_live_map, 0, AFLNET_WIN_COVERAGE_MAP_SIZE);
}

#else

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
  (void)start;
  (void)stop;
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
  (void)guard;
}

void aflnet_windows_coverage_dump(void) {}
void aflnet_windows_coverage_reset(void) {}

#endif
