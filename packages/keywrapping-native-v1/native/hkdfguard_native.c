/*
 * The native half of @runsecure/hkdfguard-keywrapping-native-v1: only what TypeScript can't do.
 *
 *   - load / unload / bind: map the verified KMS library (dlopen, LoadLibraryExW) and resolve its
 *     exports. The TypeScript loader decides whether a file may be loaded; this never searches.
 *   - wrapDek / unwrapDek / generateAndWrapDek: call the library on libuv's thread pool, so a TPM or
 *     Secure Enclave operation never blocks the event loop. Each resolves to [status, written].
 *   - hardenProcess: the Linux library's process-hardening call.
 *   - symbolImagePath (Unix): which file the dynamic linker mapped an export from (dladdr).
 *   - loadedPath (Linux): which file an already-loaded soname is bound to (RTLD_NOLOAD + dlinfo).
 *   - checkCodeSignature / productVersion (macOS): SecStaticCodeCheckValidity; kern.osproductversion.
 *   - programFilesPath / fileAttributes / securityDescriptor / describeSid / verifiedSigner (Windows):
 *     the known folder, reparse-point attributes, owner and DACL, account names, and the signer of the
 *     chain WinVerifyTrust itself validated.
 *
 * Every policy decision is made in TypeScript (the src policy files), where it is tested on every platform.
 */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* dladdr, dlinfo, RTLD_NOLOAD - before any system header */
#endif

#define NAPI_VERSION 8
#include <node_api.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#else
#include <dlfcn.h>
#if defined(__linux__)
#include <link.h>
#endif
#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <sys/sysctl.h>
#endif
#endif

/* --- N-API helpers ------------------------------------------------------------------------------ */

#define CHECK(call)                                                   \
  do {                                                                \
    if ((call) != napi_ok) {                                          \
      napi_throw_error(env, NULL, "hkdfguard_native: " #call " failed"); \
      return NULL;                                                    \
    }                                                                 \
  } while (0)

static napi_value js_undefined(napi_env env) {
  napi_value value;
  napi_get_undefined(env, &value);
  return value;
}

static napi_value js_null(napi_env env) {
  napi_value value;
  napi_get_null(env, &value);
  return value;
}

static napi_value js_string(napi_env env, const char* s) {
  napi_value value;
  napi_create_string_utf8(env, s, NAPI_AUTO_LENGTH, &value);
  return value;
}

static napi_value js_int(napi_env env, int64_t n) {
  napi_value value;
  napi_create_int64(env, n, &value);
  return value;
}

/* A UTF-8 copy of a JS string argument; free() it. NULL (with an exception pending) on failure. */
static char* utf8_arg(napi_env env, napi_value value) {
  size_t length;
  if (napi_get_value_string_utf8(env, value, NULL, 0, &length) != napi_ok) {
    napi_throw_type_error(env, NULL, "hkdfguard_native: expected a string");
    return NULL;
  }
  char* s = malloc(length + 1);
  if (s == NULL) {
    napi_throw_error(env, NULL, "hkdfguard_native: out of memory");
    return NULL;
  }
  napi_get_value_string_utf8(env, value, s, length + 1, &length);
  if (strlen(s) != length) { /* an embedded NUL would truncate the name native code sees */
    free(s);
    napi_throw_type_error(env, NULL, "hkdfguard_native: a string argument contains NUL");
    return NULL;
  }
  return s;
}

/* The bytes of a Uint8Array argument. */
static int bytes_arg(napi_env env, napi_value value, uint8_t** data, size_t* length) {
  napi_typedarray_type type;
  napi_value buffer;
  size_t offset;
  void* raw;
  if (napi_get_typedarray_info(env, value, &type, length, &raw, &buffer, &offset) != napi_ok || type != napi_uint8_array) {
    napi_throw_type_error(env, NULL, "hkdfguard_native: expected a Uint8Array");
    return 0;
  }
  if (*length > INT32_MAX) {
    napi_throw_range_error(env, NULL, "hkdfguard_native: buffer longer than 2^31-1 bytes");
    return 0;
  }
  *data = *length == 0 ? NULL : (uint8_t*)raw; /* the library rejects a NULL buffer with its invalid-argument status */
  return 1;
}

/* --- Library handle ------------------------------------------------------------------------------ */

typedef int32_t (*wrap_fn)(const char*, const uint8_t*, int32_t, uint8_t*, int32_t*);
typedef int32_t (*generate_fn)(const char*, uint8_t*, int32_t*);
typedef int32_t (*harden_fn)(void);

typedef struct {
  void* handle; /* dlopen handle or HMODULE */
  void* wrap;
  void* unwrap;
  void* generate;
  void* harden;
} kms_library;

/* A loaded library is never unloaded by the garbage collector: only unload() releases it. */
static void free_library(napi_env env, void* data, void* hint) {
  (void)env;
  (void)hint;
  free(data);
}

static kms_library* library_arg(napi_env env, napi_value value) {
  void* data = NULL;
  if (napi_get_value_external(env, value, &data) != napi_ok || data == NULL || ((kms_library*)data)->handle == NULL) {
    napi_throw_type_error(env, NULL, "hkdfguard_native: expected a loaded library");
    return NULL;
  }
  return (kms_library*)data;
}

static void* find_symbol(void* handle, const char* name) {
#if defined(_WIN32)
  return (void*)GetProcAddress((HMODULE)handle, name);
#else
  return dlsym(handle, name);
#endif
}

#if defined(_WIN32)
/* UTF-8 -> UTF-16; free() it. */
static wchar_t* to_wide(const char* s) {
  int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
  if (length <= 0) return NULL;
  wchar_t* w = malloc(sizeof(wchar_t) * (size_t)length);
  if (w != NULL) MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w, length);
  return w;
}

/* UTF-16 -> UTF-8 JS string. */
static napi_value js_wide(napi_env env, const wchar_t* w) {
  napi_value value;
  napi_create_string_utf16(env, (const char16_t*)w, NAPI_AUTO_LENGTH, &value);
  return value;
}

static void throw_last_error(napi_env env, const char* what) {
  char message[256];
  snprintf(message, sizeof message, "%s failed with Windows error %lu", what, (unsigned long)GetLastError());
  napi_throw_error(env, NULL, message);
}
#endif

/* load(path): maps the library at an absolute path, resolving every symbol now (Unix) / taking its
 * dependencies from System32 only (Windows). */
static napi_value load(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  char* path = utf8_arg(env, argv[0]);
  if (path == NULL) return NULL;

  void* handle;
#if defined(_WIN32)
  wchar_t* wide = to_wide(path);
  handle = wide == NULL ? NULL : (void*)LoadLibraryExW(wide, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
  free(wide);
  if (handle == NULL) {
    free(path);
    throw_last_error(env, "LoadLibraryExW");
    return NULL;
  }
#else
  handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (handle == NULL) {
    const char* error = dlerror();
    char message[1024];
    snprintf(message, sizeof message, "dlopen('%s') failed: %s", path, error != NULL ? error : "unknown error");
    free(path);
    napi_throw_error(env, NULL, message);
    return NULL;
  }
#endif
  free(path);

  kms_library* library = calloc(1, sizeof(kms_library));
  if (library == NULL) {
    napi_throw_error(env, NULL, "hkdfguard_native: out of memory");
    return NULL;
  }
  library->handle = handle;
  napi_value result;
  CHECK(napi_create_external(env, library, free_library, NULL, &result));
  return result;
}

/* unload(library): releases a library that failed verification after loading. */
static napi_value unload(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  kms_library* library = library_arg(env, argv[0]);
  if (library == NULL) return NULL;
#if defined(_WIN32)
  FreeLibrary((HMODULE)library->handle);
#else
  dlclose(library->handle);
#endif
  memset(library, 0, sizeof *library);
  return js_undefined(env);
}

/* bind(library, hardenSymbol | null): resolves the KMS exports, returning the names of any missing. */
static napi_value bind(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  kms_library* library = library_arg(env, argv[0]);
  if (library == NULL) return NULL;

  char* harden_name = NULL;
  napi_valuetype type;
  CHECK(napi_typeof(env, argv[1], &type));
  if (type == napi_string && (harden_name = utf8_arg(env, argv[1])) == NULL) return NULL;

  struct { const char* name; void** target; } exports[] = {
    { "hkdfguard_wrap_dek", &library->wrap },
    { "hkdfguard_unwrap_dek", &library->unwrap },
    { "hkdfguard_generate_and_wrap_dek", &library->generate },
    { harden_name, &library->harden },
  };

  napi_value missing;
  CHECK(napi_create_array(env, &missing));
  uint32_t count = 0;
  for (size_t i = 0; i < sizeof exports / sizeof exports[0]; i++) {
    if (exports[i].name == NULL) continue;
    *exports[i].target = find_symbol(library->handle, exports[i].name);
    if (*exports[i].target == NULL) {
      napi_set_element(env, missing, count++, js_string(env, exports[i].name));
    }
  }
  free(harden_name);
  return missing;
}

/* --- KMS calls on the thread pool ---------------------------------------------------------------- */

typedef struct {
  napi_async_work work;
  napi_deferred deferred;
  void* fn;
  int generate; /* hkdfguard_generate_and_wrap_dek's shape, rather than wrap/unwrap's */
  char* service;
  const uint8_t* input;
  int32_t input_length;
  uint8_t* output;
  int32_t output_length;
  napi_ref input_ref; /* keep the caller's buffers alive until the call completes */
  napi_ref output_ref;
  int32_t status;
} kms_call;

static void execute_call(napi_env env, void* data) {
  (void)env;
  kms_call* call = data;
  call->status = call->generate
    ? ((generate_fn)call->fn)(call->service, call->output, &call->output_length)
    : ((wrap_fn)call->fn)(call->service, call->input, call->input_length, call->output, &call->output_length);
}

static void complete_call(napi_env env, napi_status status, void* data) {
  kms_call* call = data;
  if (status == napi_ok) {
    napi_value result;
    napi_create_array_with_length(env, 2, &result);
    napi_set_element(env, result, 0, js_int(env, call->status));
    napi_set_element(env, result, 1, js_int(env, call->output_length));
    napi_resolve_deferred(env, call->deferred, result);
  } else {
    napi_reject_deferred(env, call->deferred, js_string(env, "hkdfguard_native: the KMS call was cancelled"));
  }
  if (call->input_ref != NULL) napi_delete_reference(env, call->input_ref);
  if (call->output_ref != NULL) napi_delete_reference(env, call->output_ref);
  napi_delete_async_work(env, call->work);
  free(call->service);
  free(call);
}

/* start_call(env, info, which): wrapDek/unwrapDek(library, service, input, output) or
 * generateAndWrapDek(library, service, output). */
static napi_value start_call(napi_env env, napi_callback_info info, int which) {
  size_t argc = 4;
  napi_value argv[4];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  kms_library* library = library_arg(env, argv[0]);
  if (library == NULL) return NULL;

  kms_call* call = calloc(1, sizeof(kms_call));
  if (call == NULL) {
    napi_throw_error(env, NULL, "hkdfguard_native: out of memory");
    return NULL;
  }
  call->generate = which == 2;
  call->fn = which == 0 ? library->wrap : which == 1 ? library->unwrap : library->generate;
  if (call->fn == NULL) {
    free(call);
    napi_throw_error(env, NULL, "hkdfguard_native: the library is not bound");
    return NULL;
  }

  call->service = utf8_arg(env, argv[1]);
  napi_value output_value = argv[call->generate ? 2 : 3];
  uint8_t* input = NULL;
  size_t input_length = 0, output_length = 0;
  if (call->service == NULL
      || (!call->generate && !bytes_arg(env, argv[2], &input, &input_length))
      || !bytes_arg(env, output_value, &call->output, &output_length)) {
    free(call->service);
    free(call);
    return NULL;
  }
  call->input = input;
  call->input_length = (int32_t)input_length;
  call->output_length = (int32_t)output_length;
  if (!call->generate) CHECK(napi_create_reference(env, argv[2], 1, &call->input_ref));
  CHECK(napi_create_reference(env, output_value, 1, &call->output_ref));

  napi_value promise, name;
  CHECK(napi_create_promise(env, &call->deferred, &promise));
  CHECK(napi_create_string_utf8(env, "hkdfguard_kms_call", NAPI_AUTO_LENGTH, &name));
  CHECK(napi_create_async_work(env, NULL, name, execute_call, complete_call, call, &call->work));
  CHECK(napi_queue_async_work(env, call->work));
  return promise;
}

static napi_value wrap_dek(napi_env env, napi_callback_info info) { return start_call(env, info, 0); }
static napi_value unwrap_dek(napi_env env, napi_callback_info info) { return start_call(env, info, 1); }
static napi_value generate_and_wrap_dek(napi_env env, napi_callback_info info) { return start_call(env, info, 2); }

/* hardenProcess(library): the status, or null when the library has no hardening call. */
static napi_value harden_process(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  kms_library* library = library_arg(env, argv[0]);
  if (library == NULL) return NULL;
  if (library->harden == NULL) return js_null(env);
  return js_int(env, ((harden_fn)library->harden)());
}

/* kekExists(library, service): [status, exists] from hkdfguard_kek_exists, or null when the library
 * has no such export. Synchronous: it is a quick lookup, used by the tests to tell "not provisioned"
 * from a failure. */
typedef int32_t (*kek_exists_fn)(const char*, int32_t*);

static napi_value kek_exists(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  kms_library* library = library_arg(env, argv[0]);
  if (library == NULL) return NULL;
  kek_exists_fn fn = (kek_exists_fn)find_symbol(library->handle, "hkdfguard_kek_exists");
  if (fn == NULL) return js_null(env);
  char* service = utf8_arg(env, argv[1]);
  if (service == NULL) return NULL;

  int32_t exists = 0;
  int32_t status = fn(service, &exists);
  free(service);
  napi_value result;
  napi_create_array_with_length(env, 2, &result);
  napi_set_element(env, result, 0, js_int(env, status));
  napi_value present;
  napi_get_boolean(env, exists != 0, &present);
  napi_set_element(env, result, 1, present);
  return result;
}

/* --- Unix: what the dynamic linker loaded ------------------------------------------------------- */

#if !defined(_WIN32)
/* symbolImagePath(library, symbol): the file dladdr says the export was mapped from, or null. */
static napi_value symbol_image_path(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  kms_library* library = library_arg(env, argv[0]);
  if (library == NULL) return NULL;
  char* symbol = utf8_arg(env, argv[1]);
  if (symbol == NULL) return NULL;

  void* address = dlsym(library->handle, symbol);
  free(symbol);
  Dl_info dl;
  if (address == NULL || dladdr(address, &dl) == 0 || dl.dli_fname == NULL) return js_null(env);
  return js_string(env, dl.dli_fname);
}
#endif

#if defined(__linux__)
/* loadedPath(soname): the path the linker recorded for the loaded object it would bind soname to,
 * or null if none is loaded. Never loads anything. */
static napi_value loaded_path(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  char* soname = utf8_arg(env, argv[0]);
  if (soname == NULL) return NULL;

  void* handle = dlopen(soname, RTLD_LAZY | RTLD_NOLOAD);
  free(soname);
  if (handle == NULL) return js_null(env);

  napi_value result = js_null(env);
  struct link_map* map = NULL;
  if (dlinfo(handle, RTLD_DI_LINKMAP, &map) == 0 && map != NULL && map->l_name != NULL && map->l_name[0] != '\0') {
    result = js_string(env, map->l_name);
  }
  dlclose(handle); /* RTLD_NOLOAD still took a reference; give it back */
  return result;
}
#endif

/* --- macOS --------------------------------------------------------------------------------------- */

#if defined(__APPLE__)
/* checkCodeSignature(path, requirement): 0 (errSecSuccess) when the signature is valid for every
 * architecture under strict validation and satisfies requirement, else the failing OSStatus. */
static napi_value check_code_signature(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  char* path = utf8_arg(env, argv[0]);
  if (path == NULL) return NULL;
  char* requirement_text = utf8_arg(env, argv[1]);
  if (requirement_text == NULL) {
    free(path);
    return NULL;
  }

  CFURLRef url = NULL;
  SecStaticCodeRef code = NULL;
  CFStringRef requirement_string = NULL;
  SecRequirementRef requirement = NULL;
  OSStatus status = -1;

  url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8*)path, (CFIndex)strlen(path), false);
  if (url == NULL) goto done;
  status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
  if (status != errSecSuccess) goto done;
  requirement_string = CFStringCreateWithCString(NULL, requirement_text, kCFStringEncodingUTF8);
  if (requirement_string == NULL) {
    status = -1;
    goto done;
  }
  status = SecRequirementCreateWithString(requirement_string, kSecCSDefaultFlags, &requirement);
  if (status != errSecSuccess) goto done;
  status = SecStaticCodeCheckValidity(code, kSecCSCheckAllArchitectures | kSecCSStrictValidate, requirement);

done:
  if (requirement != NULL) CFRelease(requirement);
  if (requirement_string != NULL) CFRelease(requirement_string);
  if (code != NULL) CFRelease(code);
  if (url != NULL) CFRelease(url);
  free(path);
  free(requirement_text);
  return js_int(env, status);
}

/* productVersion(): the macOS version, e.g. "15.4.1", or "" if it can't be read. */
static napi_value product_version(napi_env env, napi_callback_info info) {
  (void)info;
  char version[64] = "";
  size_t length = sizeof version;
  if (sysctlbyname("kern.osproductversion", version, &length, NULL, 0) != 0) version[0] = '\0';
  version[sizeof version - 1] = '\0';
  return js_string(env, version);
}
#endif

/* --- Windows ------------------------------------------------------------------------------------- */

#if defined(_WIN32)
/* programFilesPath(): %ProgramFiles% from the known-folder registry setting, not the environment. */
static napi_value program_files_path(napi_env env, napi_callback_info info) {
  (void)info;
  PWSTR path = NULL;
  if (FAILED(SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DONT_VERIFY, NULL, &path))) {
    CoTaskMemFree(path);
    napi_throw_error(env, NULL, "SHGetKnownFolderPath(FOLDERID_ProgramFiles) failed");
    return NULL;
  }
  napi_value result = js_wide(env, path);
  CoTaskMemFree(path);
  return result;
}

/* fileAttributes(path): GetFileAttributesW. */
static napi_value file_attributes(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  char* path = utf8_arg(env, argv[0]);
  if (path == NULL) return NULL;
  wchar_t* wide = to_wide(path);
  free(path);
  DWORD attributes = wide == NULL ? INVALID_FILE_ATTRIBUTES : GetFileAttributesW(wide);
  free(wide);
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    throw_last_error(env, "GetFileAttributesW");
    return NULL;
  }
  return js_int(env, attributes);
}

static napi_value sid_string(napi_env env, PSID sid) {
  LPSTR text = NULL;
  if (sid == NULL || !ConvertSidToStringSidA(sid, &text)) return js_string(env, "");
  napi_value value = js_string(env, text);
  LocalFree(text);
  return value;
}

/* securityDescriptor(path): { owner, daclAbsent, aces: [{ type, flags, mask, sid }] }. The SID is
 * read only for the ACE types whose layout puts it after the mask; any other type's is "". */
static napi_value security_descriptor(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  char* path = utf8_arg(env, argv[0]);
  if (path == NULL) return NULL;
  wchar_t* wide = to_wide(path);
  free(path);

  PSID owner = NULL;
  PACL dacl = NULL;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  DWORD error = wide == NULL ? ERROR_INVALID_NAME
    : GetNamedSecurityInfoW(wide, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL, &dacl, NULL, &descriptor);
  free(wide);
  if (error != ERROR_SUCCESS) {
    SetLastError(error);
    throw_last_error(env, "GetNamedSecurityInfoW");
    return NULL;
  }

  BOOL present = FALSE, defaulted = FALSE;
  PACL actual = NULL;
  GetSecurityDescriptorDacl(descriptor, &present, &actual, &defaulted);

  napi_value result, aces, absent;
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "owner", sid_string(env, owner));
  napi_get_boolean(env, !present || actual == NULL, &absent);
  napi_set_named_property(env, result, "daclAbsent", absent);
  napi_create_array(env, &aces);
  if (present && actual != NULL) {
    for (DWORD i = 0; i < actual->AceCount; i++) {
      LPVOID raw = NULL;
      if (!GetAce(actual, i, &raw)) {
        LocalFree(descriptor);
        throw_last_error(env, "GetAce");
        return NULL;
      }
      ACE_HEADER* header = raw;
      ACCESS_ALLOWED_ACE* ace = raw; /* the mask follows the header in every standard ACE */
      napi_value entry;
      napi_create_object(env, &entry);
      napi_set_named_property(env, entry, "type", js_int(env, header->AceType));
      napi_set_named_property(env, entry, "flags", js_int(env, header->AceFlags));
      napi_set_named_property(env, entry, "mask", js_int(env, ace->Mask));
      int sid_follows_mask = header->AceType == ACCESS_ALLOWED_ACE_TYPE || header->AceType == ACCESS_DENIED_ACE_TYPE
        || header->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE || header->AceType == ACCESS_DENIED_CALLBACK_ACE_TYPE;
      napi_set_named_property(env, entry, "sid", sid_follows_mask ? sid_string(env, (PSID)&ace->SidStart) : js_string(env, ""));
      napi_set_element(env, aces, i, entry);
    }
  }
  napi_set_named_property(env, result, "aces", aces);
  LocalFree(descriptor);
  return result;
}

/* describeSid(sid): "DOMAIN\account (S-...)", or the SID itself if it maps to no account here. */
static napi_value describe_sid(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  char* text = utf8_arg(env, argv[0]);
  if (text == NULL) return NULL;

  PSID sid = NULL;
  napi_value result = js_string(env, text);
  if (ConvertStringSidToSidA(text, &sid)) {
    char name[256], domain[256], described[600];
    DWORD name_length = sizeof name, domain_length = sizeof domain;
    SID_NAME_USE use;
    if (LookupAccountSidA(NULL, sid, name, &name_length, domain, &domain_length, &use)) {
      snprintf(described, sizeof described, "%s%s%s (%s)", domain, domain[0] != '\0' ? "\\" : "", name, text);
      result = js_string(env, described);
    }
    LocalFree(sid);
  }
  free(text);
  return result;
}

/* verifiedSigner(path): WinVerifyTrust (generic Authenticode policy, no revocation, no network) and
 * the signer read from the chain it validated: { subject, ekus, rootCertificate } - or { status }
 * when the signature isn't valid and trusted, or { error } when the chain can't be read. */
static napi_value verified_signer(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  char* path = utf8_arg(env, argv[0]);
  if (path == NULL) return NULL;
  wchar_t* wide = to_wide(path);
  free(path);
  if (wide == NULL) {
    napi_throw_error(env, NULL, "verifiedSigner: invalid path");
    return NULL;
  }

  WINTRUST_FILE_INFO file = { sizeof file };
  file.pcwszFilePath = wide;
  WINTRUST_DATA data = { sizeof data };
  data.dwUIChoice = WTD_UI_NONE;
  data.fdwRevocationChecks = WTD_REVOKE_NONE;
  data.dwUnionChoice = WTD_CHOICE_FILE;
  data.pFile = &file;
  data.dwStateAction = WTD_STATEACTION_VERIFY;
  data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
  GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

  napi_value result;
  napi_create_object(env, &result);
  LONG status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &data);
  const char* problem = NULL;

  if (status != 0) {
    napi_set_named_property(env, result, "status", js_int(env, (uint32_t)status));
    goto close;
  }

  CRYPT_PROVIDER_DATA* provider = WTHelperProvDataFromStateData(data.hWVTStateData);
  CRYPT_PROVIDER_SGNR* signer = provider == NULL ? NULL : WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0);
  const CERT_CHAIN_CONTEXT* chain = signer == NULL ? NULL : signer->pChainContext;
  /* An Authenticode signer's chain is a single simple chain, leaf first and root last; anything
   * else is refused rather than guessed at. */
  if (chain == NULL || chain->cChain != 1 || chain->rgpChain[0]->cElement == 0) {
    problem = "the signer's certificate chain could not be read, or is not a single chain";
    goto close;
  }
  const CERT_SIMPLE_CHAIN* simple = chain->rgpChain[0];
  const CERT_CONTEXT* leaf = simple->rgpElement[0]->pCertContext;
  const CERT_CONTEXT* root = simple->rgpElement[simple->cElement - 1]->pCertContext;

  /* The subject as Windows (and .NET's X509Certificate.Subject) renders it: X.500, CN first. */
  DWORD flags = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;
  DWORD length = CertNameToStrW(X509_ASN_ENCODING, &leaf->pCertInfo->Subject, flags, NULL, 0);
  wchar_t* subject = length == 0 ? NULL : malloc(sizeof(wchar_t) * length);
  if (subject == NULL) {
    problem = "the signer's subject could not be read";
    goto close;
  }
  CertNameToStrW(X509_ASN_ENCODING, &leaf->pCertInfo->Subject, flags, subject, length);
  napi_set_named_property(env, result, "subject", js_wide(env, subject));
  free(subject);

  napi_value ekus;
  napi_create_array(env, &ekus);
  CERT_EXTENSION* extension = CertFindExtension(szOID_ENHANCED_KEY_USAGE, leaf->pCertInfo->cExtension, leaf->pCertInfo->rgExtension);
  if (extension != NULL) {
    DWORD size = 0;
    if (!CryptDecodeObject(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, extension->Value.pbData, extension->Value.cbData, 0, NULL, &size)) {
      problem = "the signer's extended key usage could not be decoded";
      goto close;
    }
    CERT_ENHANCED_KEY_USAGE* usage = malloc(size);
    if (usage == NULL
        || !CryptDecodeObject(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, extension->Value.pbData, extension->Value.cbData, 0, usage, &size)) {
      free(usage);
      problem = "the signer's extended key usage could not be decoded";
      goto close;
    }
    for (DWORD i = 0; i < usage->cUsageIdentifier; i++) {
      napi_set_element(env, ekus, i, js_string(env, usage->rgpszUsageIdentifier[i]));
    }
    free(usage);
  }
  napi_set_named_property(env, result, "ekus", ekus);

  void* copy;
  napi_value root_bytes, root_array;
  napi_create_arraybuffer(env, root->cbCertEncoded, &copy, &root_bytes);
  memcpy(copy, root->pbCertEncoded, root->cbCertEncoded);
  napi_create_typedarray(env, napi_uint8_array, root->cbCertEncoded, root_bytes, 0, &root_array);
  napi_set_named_property(env, result, "rootCertificate", root_array);

close:
  /* Release the state the verify call allocated, whatever it returned; everything read from the
   * chain was copied out above. */
  data.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &data);
  free(wide);
  if (problem != NULL) {
    napi_create_object(env, &result);
    napi_set_named_property(env, result, "error", js_string(env, problem));
  }
  return result;
}
#endif

/* --- Module -------------------------------------------------------------------------------------- */

NAPI_MODULE_INIT() {
  napi_property_descriptor properties[] = {
    { "load", NULL, load, NULL, NULL, NULL, napi_enumerable, NULL },
    { "unload", NULL, unload, NULL, NULL, NULL, napi_enumerable, NULL },
    { "bind", NULL, bind, NULL, NULL, NULL, napi_enumerable, NULL },
    { "wrapDek", NULL, wrap_dek, NULL, NULL, NULL, napi_enumerable, NULL },
    { "unwrapDek", NULL, unwrap_dek, NULL, NULL, NULL, napi_enumerable, NULL },
    { "generateAndWrapDek", NULL, generate_and_wrap_dek, NULL, NULL, NULL, napi_enumerable, NULL },
    { "hardenProcess", NULL, harden_process, NULL, NULL, NULL, napi_enumerable, NULL },
    { "kekExists", NULL, kek_exists, NULL, NULL, NULL, napi_enumerable, NULL },
#if !defined(_WIN32)
    { "symbolImagePath", NULL, symbol_image_path, NULL, NULL, NULL, napi_enumerable, NULL },
#endif
#if defined(__linux__)
    { "loadedPath", NULL, loaded_path, NULL, NULL, NULL, napi_enumerable, NULL },
#endif
#if defined(__APPLE__)
    { "checkCodeSignature", NULL, check_code_signature, NULL, NULL, NULL, napi_enumerable, NULL },
    { "productVersion", NULL, product_version, NULL, NULL, NULL, napi_enumerable, NULL },
#endif
#if defined(_WIN32)
    { "programFilesPath", NULL, program_files_path, NULL, NULL, NULL, napi_enumerable, NULL },
    { "fileAttributes", NULL, file_attributes, NULL, NULL, NULL, napi_enumerable, NULL },
    { "securityDescriptor", NULL, security_descriptor, NULL, NULL, NULL, napi_enumerable, NULL },
    { "describeSid", NULL, describe_sid, NULL, NULL, NULL, napi_enumerable, NULL },
    { "verifiedSigner", NULL, verified_signer, NULL, NULL, NULL, napi_enumerable, NULL },
#endif
  };
  if (napi_define_properties(env, exports, sizeof properties / sizeof properties[0], properties) != napi_ok) {
    return NULL;
  }
  return exports;
}
