/*
 * The native half of @runsecure/hkdfguard-securefile: the Win32 calls a Windows key-file read needs
 * and Node.js doesn't expose. It returns facts only; every decision - what is trusted, what is
 * refused, and how each failure is reported - is made in TypeScript (src/windows.ts and
 * src/trustedkeyfile.ts), where it is tested on every platform.
 *
 *   - fullPath / longPath: GetFullPathNameW (a relative path resolved against the working directory)
 *     and GetLongPathNameW (an 8.3 short name expanded).
 *   - driveType / fileAttributes: GetDriveTypeW of a drive root; GetFileAttributesW of a folder, its
 *     reparse-point bit in particular.
 *   - openFile / finalPath / fileSecurity / readFile / closeFile: the key file opened with read
 *     sharing only (CreateFileW), the path its handle actually refers to
 *     (GetFinalPathNameByHandleW), its owner and DACL read through that same handle
 *     (GetSecurityInfo), and its contents read through it (ReadFile).
 *   - namedSecurity: a folder's owner and DACL, by path (GetNamedSecurityInfoW).
 *   - sddlSecurity: a descriptor written in SDDL, parsed exactly as the others are - for the tests.
 *   - canonicalSid / accountName: a SID string's canonical form; the account a SID names.
 *
 * Only kernel32 and advapi32 are called, both linked at build time, never loaded by name at run time;
 * the linker's /DEPENDENTLOADFLAG (binding.gyp) makes the loader resolve them from System32 only,
 * never from the application's directory or PATH. Windows only: on other platforms the add-on isn't
 * built (scripts/build-addon.js), and this file compiles to a module with no exports.
 */
#define NAPI_VERSION 8
#include <node_api.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

/* The longest path Windows supports, plus its terminator. */
#define MAX_PATH_CHARS 32768

#define CHECK(call)                                                       \
  do {                                                                    \
    if ((call) != napi_ok) {                                              \
      napi_throw_error(env, NULL, "hkdfguard_securefile: " #call " failed"); \
      return NULL;                                                        \
    }                                                                     \
  } while (0)

/* --- N-API helpers ------------------------------------------------------------------------------ */

static napi_value js_null(napi_env env) {
  napi_value value;
  napi_get_null(env, &value);
  return value;
}

static napi_value js_undefined(napi_env env) {
  napi_value value;
  napi_get_undefined(env, &value);
  return value;
}

static napi_value js_uint(napi_env env, uint32_t n) {
  napi_value value;
  napi_create_uint32(env, n, &value);
  return value;
}

static napi_value js_wide(napi_env env, const wchar_t* w) {
  napi_value value;
  napi_create_string_utf16(env, (const char16_t*)w, NAPI_AUTO_LENGTH, &value);
  return value;
}

static void throw_win32(napi_env env, const char* what, DWORD error) {
  char message[256];
  snprintf(message, sizeof message, "%s failed with Windows error %lu", what, (unsigned long)error);
  napi_throw_error(env, NULL, message);
}

/* A UTF-16 copy of a JS string argument; free() it. NULL (with an exception pending) on failure,
 * including a string with an embedded NUL, which would truncate the path Windows sees. */
static wchar_t* wide_arg(napi_env env, napi_value value) {
  size_t length;
  if (napi_get_value_string_utf16(env, value, NULL, 0, &length) != napi_ok) {
    napi_throw_type_error(env, NULL, "hkdfguard_securefile: expected a string");
    return NULL;
  }
  wchar_t* w = malloc(sizeof(wchar_t) * (length + 1));
  if (w == NULL) {
    napi_throw_error(env, NULL, "hkdfguard_securefile: out of memory");
    return NULL;
  }
  napi_get_value_string_utf16(env, value, (char16_t*)w, length + 1, &length);
  if (wcslen(w) != length) {
    free(w);
    napi_throw_type_error(env, NULL, "hkdfguard_securefile: a string argument contains NUL");
    return NULL;
  }
  return w;
}

/* The one string argument of a call; NULL with an exception pending on failure. */
static wchar_t* single_wide_arg(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc < 1) {
    napi_throw_type_error(env, NULL, "hkdfguard_securefile: expected one argument");
    return NULL;
  }
  return wide_arg(env, argv[0]);
}

/* --- Paths -------------------------------------------------------------------------------------- */

/* fullPath(path): GetFullPathNameW - absolute and normalized, a relative path resolved against the
 * working directory. Short names are left as they are; see longPath. */
static napi_value full_path(napi_env env, napi_callback_info info) {
  wchar_t* path = single_wide_arg(env, info);
  if (path == NULL) return NULL;
  wchar_t* buffer = malloc(sizeof(wchar_t) * MAX_PATH_CHARS);
  if (buffer == NULL) {
    free(path);
    napi_throw_error(env, NULL, "hkdfguard_securefile: out of memory");
    return NULL;
  }
  DWORD length = GetFullPathNameW(path, MAX_PATH_CHARS, buffer, NULL);
  DWORD error = GetLastError();
  free(path);
  napi_value result = NULL;
  if (length == 0 || length >= MAX_PATH_CHARS) {
    throw_win32(env, "GetFullPathNameW", length == 0 ? error : ERROR_FILENAME_EXCED_RANGE);
  } else {
    result = js_wide(env, buffer);
  }
  free(buffer);
  return result;
}

/* longPath(path): GetLongPathNameW - every 8.3 short name expanded - or null when it fails, as it
 * does for a path whose last component doesn't exist. */
static napi_value long_path(napi_env env, napi_callback_info info) {
  wchar_t* path = single_wide_arg(env, info);
  if (path == NULL) return NULL;
  wchar_t* buffer = malloc(sizeof(wchar_t) * MAX_PATH_CHARS);
  if (buffer == NULL) {
    free(path);
    napi_throw_error(env, NULL, "hkdfguard_securefile: out of memory");
    return NULL;
  }
  DWORD length = GetLongPathNameW(path, buffer, MAX_PATH_CHARS);
  free(path);
  napi_value result = length == 0 || length >= MAX_PATH_CHARS ? js_null(env) : js_wide(env, buffer);
  free(buffer);
  return result;
}

/* driveType(root): GetDriveTypeW of a drive root such as "C:\", a DRIVE_* value. */
static napi_value drive_type(napi_env env, napi_callback_info info) {
  wchar_t* root = single_wide_arg(env, info);
  if (root == NULL) return NULL;
  UINT type = GetDriveTypeW(root);
  free(root);
  return js_uint(env, type);
}

/* fileAttributes(path): GetFileAttributesW - the item's own attributes, a link not followed - or
 * INVALID_FILE_ATTRIBUTES (every bit set, the reparse-point bit included) when it can't be read. */
static napi_value file_attributes(napi_env env, napi_callback_info info) {
  wchar_t* path = single_wide_arg(env, info);
  if (path == NULL) return NULL;
  DWORD attributes = GetFileAttributesW(path);
  free(path);
  return js_uint(env, attributes);
}

/* --- Security descriptors ----------------------------------------------------------------------- */

/* A SID as its string form, or null if there is none or it isn't valid. */
static napi_value sid_value(napi_env env, PSID sid) {
  LPWSTR text = NULL;
  if (sid == NULL || !IsValidSid(sid) || !ConvertSidToStringSidW(sid, &text)) return js_null(env);
  napi_value value = js_wide(env, text);
  LocalFree(text);
  return value;
}

/* { owner, daclAbsent, aces: [{ type, flags, mask, sid }] } for a security descriptor. owner is null
 * when there is none; daclAbsent is true for a missing or NULL DACL, which grants everyone full
 * control. An ACE's sid is read only for the four types whose layout puts it right after the mask -
 * allowed, denied and their callback forms - and is null for every other type (the object ACEs). */
static napi_value describe_descriptor(napi_env env, PSECURITY_DESCRIPTOR descriptor) {
  PSID owner = NULL;
  BOOL defaulted = FALSE;
  if (!GetSecurityDescriptorOwner(descriptor, &owner, &defaulted)) {
    throw_win32(env, "GetSecurityDescriptorOwner", GetLastError());
    return NULL;
  }
  BOOL present = FALSE;
  PACL dacl = NULL;
  if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted)) {
    throw_win32(env, "GetSecurityDescriptorDacl", GetLastError());
    return NULL;
  }

  napi_value result, aces, absent;
  CHECK(napi_create_object(env, &result));
  CHECK(napi_set_named_property(env, result, "owner", sid_value(env, owner)));
  CHECK(napi_get_boolean(env, !present || dacl == NULL, &absent));
  CHECK(napi_set_named_property(env, result, "daclAbsent", absent));
  CHECK(napi_create_array(env, &aces));
  if (present && dacl != NULL) {
    for (DWORD i = 0; i < dacl->AceCount; i++) {
      LPVOID raw = NULL;
      if (!GetAce(dacl, i, &raw) || raw == NULL) {
        throw_win32(env, "GetAce", GetLastError());
        return NULL;
      }
      const ACE_HEADER* header = raw;
      const ACCESS_ALLOWED_ACE* ace = raw; /* the mask follows the header in every ACE type */
      int sid_follows_mask = header->AceType == ACCESS_ALLOWED_ACE_TYPE || header->AceType == ACCESS_DENIED_ACE_TYPE
        || header->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE || header->AceType == ACCESS_DENIED_CALLBACK_ACE_TYPE;
      napi_value entry;
      CHECK(napi_create_object(env, &entry));
      CHECK(napi_set_named_property(env, entry, "type", js_uint(env, header->AceType)));
      CHECK(napi_set_named_property(env, entry, "flags", js_uint(env, header->AceFlags)));
      CHECK(napi_set_named_property(env, entry, "mask", js_uint(env, header->AceSize >= 8 ? ace->Mask : 0)));
      CHECK(napi_set_named_property(env, entry, "sid",
        sid_follows_mask && header->AceSize > 8 ? sid_value(env, (PSID)&ace->SidStart) : js_null(env)));
      CHECK(napi_set_element(env, aces, i, entry));
    }
  }
  CHECK(napi_set_named_property(env, result, "aces", aces));
  return result;
}

/* A descriptor the system allocated, described and freed. */
static napi_value describe_and_free(napi_env env, PSECURITY_DESCRIPTOR descriptor) {
  napi_value result = describe_descriptor(env, descriptor);
  LocalFree(descriptor);
  return result;
}

/* namedSecurity(path): a file or folder's owner and DACL, by path - or the Windows error number. */
static napi_value named_security(napi_env env, napi_callback_info info) {
  wchar_t* path = single_wide_arg(env, info);
  if (path == NULL) return NULL;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  DWORD error = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                      NULL, NULL, NULL, NULL, &descriptor);
  free(path);
  if (error != ERROR_SUCCESS) return js_uint(env, error);
  return describe_and_free(env, descriptor);
}

/* sddlSecurity(sddl): a descriptor written in SDDL, described as the others are - or null if the
 * SDDL isn't valid. For the tests: it builds descriptors a real file would be hard to give. */
static napi_value sddl_security(napi_env env, napi_callback_info info) {
  wchar_t* sddl = single_wide_arg(env, info);
  if (sddl == NULL) return NULL;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  BOOL converted = ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, NULL);
  free(sddl);
  if (!converted) return js_null(env);
  return describe_and_free(env, descriptor);
}

/* canonicalSid(text): a SID string in its canonical form, as ConvertStringSidToSidW reads it (it
 * also accepts the SDDL aliases, such as "BA"), or null if it isn't a SID. */
static napi_value canonical_sid(napi_env env, napi_callback_info info) {
  wchar_t* text = single_wide_arg(env, info);
  if (text == NULL) return NULL;
  PSID sid = NULL;
  BOOL converted = ConvertStringSidToSidW(text, &sid);
  free(text);
  if (!converted) return js_null(env);
  napi_value result = sid_value(env, sid);
  LocalFree(sid);
  return result;
}

/* accountName(sid): the account a SID string names, as DOMAIN\name (or name alone), or null if it
 * names none here. For messages only. */
static napi_value account_name(napi_env env, napi_callback_info info) {
  wchar_t* text = single_wide_arg(env, info);
  if (text == NULL) return NULL;
  PSID sid = NULL;
  BOOL converted = ConvertStringSidToSidW(text, &sid);
  free(text);
  if (!converted) return js_null(env);

  wchar_t name[256], domain[256], described[520];
  DWORD name_length = 256, domain_length = 256;
  SID_NAME_USE use;
  napi_value result = js_null(env);
  if (LookupAccountSidW(NULL, sid, name, &name_length, domain, &domain_length, &use)) {
    if (domain[0] != L'\0') {
      _snwprintf_s(described, 520, _TRUNCATE, L"%s\\%s", domain, name);
      result = js_wide(env, described);
    } else {
      result = js_wide(env, name);
    }
  }
  LocalFree(sid);
  return result;
}

/* --- The opened file ---------------------------------------------------------------------------- */

typedef struct {
  HANDLE handle; /* INVALID_HANDLE_VALUE once closed */
} open_file;

static void free_open_file(napi_env env, void* data, void* hint) {
  (void)env;
  (void)hint;
  open_file* file = data;
  if (file->handle != INVALID_HANDLE_VALUE) CloseHandle(file->handle);
  free(file);
}

/* The open file a handle argument names; NULL with an exception pending if it isn't one or is closed. */
static open_file* file_arg(napi_env env, napi_value value) {
  napi_valuetype type;
  void* data = NULL;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_external || napi_get_value_external(env, value, &data) != napi_ok
      || data == NULL) {
    napi_throw_type_error(env, NULL, "hkdfguard_securefile: expected an open key file");
    return NULL;
  }
  open_file* file = data;
  if (file->handle == INVALID_HANDLE_VALUE) {
    napi_throw_error(env, NULL, "hkdfguard_securefile: the key file has been closed");
    return NULL;
  }
  return file;
}

/* openFile(path): the file opened for reading with read sharing only - refused if another process
 * has it open for writing, and no one can open it for writing while it is held - as an opaque
 * handle, or the Windows error number. Closed by closeFile, or when the handle is collected. */
static napi_value open_file_call(napi_env env, napi_callback_info info) {
  wchar_t* path = single_wide_arg(env, info);
  if (path == NULL) return NULL;
  HANDLE handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  DWORD error = GetLastError();
  free(path);
  if (handle == INVALID_HANDLE_VALUE) return js_uint(env, error);

  open_file* file = malloc(sizeof *file);
  if (file == NULL) {
    CloseHandle(handle);
    napi_throw_error(env, NULL, "hkdfguard_securefile: out of memory");
    return NULL;
  }
  file->handle = handle;
  napi_value result;
  if (napi_create_external(env, file, free_open_file, NULL, &result) != napi_ok) {
    CloseHandle(handle);
    free(file);
    napi_throw_error(env, NULL, "hkdfguard_securefile: napi_create_external failed");
    return NULL;
  }
  return result;
}

/* finalPath(file): GetFinalPathNameByHandleW (FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) - the path of
 * the file the handle actually refers to, after every symbolic link, junction, mount point and
 * substituted drive is resolved, in long-name form (\\?\C:\...). */
static napi_value final_path(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  open_file* file = file_arg(env, argv[0]);
  if (file == NULL) return NULL;

  DWORD capacity = 512;
  for (;;) {
    wchar_t* buffer = malloc(sizeof(wchar_t) * capacity);
    if (buffer == NULL) {
      napi_throw_error(env, NULL, "hkdfguard_securefile: out of memory");
      return NULL;
    }
    DWORD length = GetFinalPathNameByHandleW(file->handle, buffer, capacity, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (length == 0) {
      DWORD error = GetLastError();
      free(buffer);
      throw_win32(env, "GetFinalPathNameByHandleW", error);
      return NULL;
    }
    if (length < capacity) {
      napi_value result = js_wide(env, buffer);
      free(buffer);
      return result;
    }
    free(buffer);
    if (length > MAX_PATH_CHARS) {
      throw_win32(env, "GetFinalPathNameByHandleW", ERROR_FILENAME_EXCED_RANGE);
      return NULL;
    }
    capacity = length; /* too small: length is the size needed, terminator included */
  }
}

/* fileSecurity(file): the opened file's owner and DACL, read through its handle - or the Windows
 * error number. */
static napi_value file_security(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  open_file* file = file_arg(env, argv[0]);
  if (file == NULL) return NULL;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  DWORD error = GetSecurityInfo(file->handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                NULL, NULL, NULL, NULL, &descriptor);
  if (error != ERROR_SUCCESS) return js_uint(env, error);
  return describe_and_free(env, descriptor);
}

/* readFile(file, view): ReadFile - up to view.length bytes straight into the Uint8Array, no copy in
 * between. Returns the count; 0 at the end of the file. */
static napi_value read_file(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc < 2) {
    napi_throw_type_error(env, NULL, "hkdfguard_securefile: expected a key file and a Uint8Array");
    return NULL;
  }
  open_file* file = file_arg(env, argv[0]);
  if (file == NULL) return NULL;

  napi_typedarray_type type;
  size_t length;
  void* data = NULL;
  napi_value buffer;
  size_t offset;
  if (napi_get_typedarray_info(env, argv[1], &type, &length, &data, &buffer, &offset) != napi_ok || type != napi_uint8_array) {
    napi_throw_type_error(env, NULL, "hkdfguard_securefile: expected a Uint8Array");
    return NULL;
  }
  if (length == 0) return js_uint(env, 0);
  DWORD request = length > 0x7FFFFFFF ? 0x7FFFFFFF : (DWORD)length;
  DWORD read = 0;
  if (!ReadFile(file->handle, data, request, &read, NULL)) {
    throw_win32(env, "ReadFile", GetLastError());
    return NULL;
  }
  return js_uint(env, read);
}

/* closeFile(file): closes the handle. Safe to call more than once. */
static napi_value close_file(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  void* data = NULL;
  napi_valuetype type;
  if (argc >= 1 && napi_typeof(env, argv[0], &type) == napi_ok && type == napi_external
      && napi_get_value_external(env, argv[0], &data) == napi_ok && data != NULL) {
    open_file* file = data;
    if (file->handle != INVALID_HANDLE_VALUE) {
      CloseHandle(file->handle);
      file->handle = INVALID_HANDLE_VALUE;
    }
  }
  return js_undefined(env);
}
#endif

/* --- Module ------------------------------------------------------------------------------------- */

NAPI_MODULE_INIT() {
#if defined(_WIN32)
  napi_property_descriptor properties[] = {
    { "fullPath", NULL, full_path, NULL, NULL, NULL, napi_enumerable, NULL },
    { "longPath", NULL, long_path, NULL, NULL, NULL, napi_enumerable, NULL },
    { "driveType", NULL, drive_type, NULL, NULL, NULL, napi_enumerable, NULL },
    { "fileAttributes", NULL, file_attributes, NULL, NULL, NULL, napi_enumerable, NULL },
    { "openFile", NULL, open_file_call, NULL, NULL, NULL, napi_enumerable, NULL },
    { "finalPath", NULL, final_path, NULL, NULL, NULL, napi_enumerable, NULL },
    { "fileSecurity", NULL, file_security, NULL, NULL, NULL, napi_enumerable, NULL },
    { "readFile", NULL, read_file, NULL, NULL, NULL, napi_enumerable, NULL },
    { "closeFile", NULL, close_file, NULL, NULL, NULL, napi_enumerable, NULL },
    { "namedSecurity", NULL, named_security, NULL, NULL, NULL, napi_enumerable, NULL },
    { "sddlSecurity", NULL, sddl_security, NULL, NULL, NULL, napi_enumerable, NULL },
    { "canonicalSid", NULL, canonical_sid, NULL, NULL, NULL, napi_enumerable, NULL },
    { "accountName", NULL, account_name, NULL, NULL, NULL, napi_enumerable, NULL },
  };
  if (napi_define_properties(env, exports, sizeof properties / sizeof properties[0], properties) != napi_ok) {
    return NULL;
  }
#else
  (void)env;
#endif
  return exports;
}
