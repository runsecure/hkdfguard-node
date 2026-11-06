/*
 * The native half of @runsecure/hkdfguard-options-certificate: only what node:crypto can't do - reach
 * a private key an operating system store holds, without ever exporting it.
 *
 *   Windows (crypt32, CNG):
 *     windowsReadStore(location, name): every certificate in a system store, opened read-only and
 *       only if it exists (CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG): its DER, whether
 *       the store holds its private key, and a handle to a duplicate of its context; null for a store
 *       that doesn't exist or can't be opened, as .NET's X509Store reads it.
 *     windowsFreeCertificate(handle): frees the context now (the finalizer would, later).
 *     windowsOpenKey(handle): the certificate's private key through CNG alone, silently
 *       (CryptAcquireCertificatePrivateKey with CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG and
 *       CRYPT_ACQUIRE_SILENT_FLAG): a key handle, or { error, status } when it can't be opened.
 *     windowsSign(key, digest, hash, padding, saltLength): NCryptSignHash on libuv's thread pool.
 *     windowsDecrypt(key, ciphertext, padding, hash, label): NCryptDecrypt on libuv's thread pool.
 *   macOS (Security framework):
 *     macReadKeychain(location): the identities (certificates with their keys) and the certificates of
 *       one keychain - the login keychain of the effective user (from the account database, never
 *       $HOME) for CurrentUser, the System keychain for LocalMachine - and only that keychain.
 *     macOpenKey(identity): SecIdentityCopyPrivateKey.
 *     macSign(key, digest, algorithm), macDecrypt(key, ciphertext, algorithm): SecKeyCreateSignature
 *       and SecKeyCreateDecryptedData on libuv's thread pool.
 *     macReleaseIdentity(identity).
 *   Both: releaseKey(key).
 *
 * Nothing here exports a key, asks for one to be exportable, or reads one into the process: every
 * signature and decryption is the store's own call. The operations work on the add-on's own copies of
 * their inputs; a decryption's plaintext is copied into a new Buffer on the main thread and the
 * native copy zeroed. A key handle is released once release has been asked for and no operation is in
 * flight - each operation holds a reference to the key's JS handle, so it can't be finalized under one.
 * Every decision - which certificate, which algorithm, what a status means - is made in TypeScript.
 */
#define NAPI_VERSION 8
#include <node_api.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#elif defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#endif

/* --- N-API helpers ------------------------------------------------------------------------------ */

#define CHECK(call)                                                          \
  do {                                                                       \
    if ((call) != napi_ok) {                                                 \
      napi_throw_error(env, NULL, "hkdfguard_certificate: " #call " failed"); \
      return NULL;                                                           \
    }                                                                        \
  } while (0)

#if defined(_WIN32) || defined(__APPLE__)
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

static napi_value js_string(napi_env env, const char* s) {
  napi_value value;
  napi_create_string_utf8(env, s, NAPI_AUTO_LENGTH, &value);
  return value;
}

static napi_value js_number(napi_env env, double n) {
  napi_value value;
  napi_create_double(env, n, &value);
  return value;
}

#if defined(_WIN32)
static napi_value js_boolean(napi_env env, int b) {
  napi_value value;
  napi_get_boolean(env, b != 0, &value);
  return value;
}
#endif

/* A new Buffer holding a copy of length bytes at data. */
static napi_value js_buffer_copy(napi_env env, const void* data, size_t length) {
  napi_value value;
  void* copied;
  if (napi_create_buffer_copy(env, length, length == 0 ? "" : data, &copied, &value) != napi_ok) return NULL;
  return value;
}

/* An int32 argument. */
static int int_arg(napi_env env, napi_value value, int32_t* out) {
  if (napi_get_value_int32(env, value, out) != napi_ok) {
    napi_throw_type_error(env, NULL, "hkdfguard_certificate: expected a number");
    return 0;
  }
  return 1;
}

/* A copy of a Uint8Array argument's bytes, malloc'd (at least one byte); free it. NULL, with an
 * exception pending, on failure. The copy is the operation's own: a caller's ArrayBuffer may be
 * detached, or reused, while the operation runs on the thread pool. */
static uint8_t* bytes_copy_arg(napi_env env, napi_value value, size_t* length) {
  napi_typedarray_type type;
  napi_value buffer;
  size_t offset;
  void* raw;
  if (napi_get_typedarray_info(env, value, &type, length, &raw, &buffer, &offset) != napi_ok || type != napi_uint8_array) {
    napi_throw_type_error(env, NULL, "hkdfguard_certificate: expected a Uint8Array");
    return NULL;
  }
  uint8_t* copy = malloc(*length == 0 ? 1 : *length);
  if (copy == NULL) {
    napi_throw_error(env, NULL, "hkdfguard_certificate: out of memory");
    return NULL;
  }
  if (*length > 0) memcpy(copy, raw, *length);
  return copy;
}

/* Zeroes memory the compiler may not optimise away. */
static void wipe(void* data, size_t length) {
#if defined(_WIN32)
  SecureZeroMemory(data, length);
#else
  volatile uint8_t* p = (volatile uint8_t*)data;
  while (length-- > 0) *p++ = 0;
#endif
}

/* An Error with a numeric `status` property, for a promise to reject with. */
static napi_value status_error(napi_env env, const char* message, double status) {
  napi_value text, error;
  napi_create_string_utf8(env, message, NAPI_AUTO_LENGTH, &text);
  napi_create_error(env, NULL, text, &error);
  napi_set_named_property(env, error, "status", js_number(env, status));
  return error;
}

/* --- Key handles -------------------------------------------------------------------------------- */

/* A private key the store holds, behind a JS external. All of its fields are touched on the main
 * thread only, but the OS handle, which a thread-pool operation uses while inflight counts it. */
typedef struct os_key {
  int inflight; /* operations queued or running */
  int closed;   /* release was asked for: no new operation starts, and the handle goes once inflight is 0 */
#if defined(_WIN32)
  NCRYPT_KEY_HANDLE handle;
  int owned;              /* whether the handle is ours to free, rather than the certificate context's */
  PCCERT_CONTEXT context; /* a duplicate, holding the context - and a handle it owns - alive */
#else
  SecKeyRef key;
#endif
} os_key;

static void close_key_handle(os_key* key) {
#if defined(_WIN32)
  if (key->owned && key->handle != 0) NCryptFreeObject(key->handle);
  key->handle = 0;
  if (key->context != NULL) CertFreeCertificateContext(key->context);
  key->context = NULL;
#else
  if (key->key != NULL) CFRelease(key->key);
  key->key = NULL;
#endif
}

static void finalize_key(napi_env env, void* data, void* hint) {
  (void)env;
  (void)hint;
  os_key* key = data;
  close_key_handle(key); /* unreachable from JS, and no operation holds it: release it now */
  free(key);
}

static napi_value wrap_key(napi_env env, os_key* key) {
  napi_value external;
  if (napi_create_external(env, key, finalize_key, NULL, &external) != napi_ok) {
    close_key_handle(key);
    free(key);
    napi_throw_error(env, NULL, "hkdfguard_certificate: napi_create_external failed");
    return NULL;
  }
  return external;
}

static os_key* key_arg(napi_env env, napi_value value) {
  void* data = NULL;
  if (napi_get_value_external(env, value, &data) != napi_ok || data == NULL) {
    napi_throw_type_error(env, NULL, "hkdfguard_certificate: expected a key handle");
    return NULL;
  }
  return data;
}

/* releaseKey(key): no new operation may start; the handle is released now, or when the last
 * operation in flight completes. */
static napi_value release_key(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  os_key* key = key_arg(env, argv[0]);
  if (key == NULL) return NULL;
  if (!key->closed) {
    key->closed = 1;
    if (key->inflight == 0) close_key_handle(key);
  }
  return js_undefined(env);
}

/* --- Operations on the thread pool ---------------------------------------------------------------- */

typedef struct key_call {
  napi_async_work work;
  napi_deferred deferred;
  napi_ref key_ref; /* keeps the key's external - and so the key - alive while the call runs */
  os_key* key;
  int decrypt;
  uint8_t* input;
  size_t input_length;
  uint8_t* label;
  size_t label_length;
  int32_t hash;
  int32_t padding;
  int32_t salt_length;
  int32_t algorithm;
  uint8_t* output;
  size_t output_capacity;
  size_t output_length;
  double status; /* 0 for success */
  char message[256];
} key_call;

static void free_call(key_call* call) {
  if (call->output != NULL) {
    wipe(call->output, call->output_capacity);
    free(call->output);
  }
  free(call->input);
  free(call->label);
  free(call);
}

#if defined(_WIN32)
static LPCWSTR cng_hash(int32_t hash) {
  switch (hash) {
    case 1: return BCRYPT_SHA1_ALGORITHM;
    case 256: return BCRYPT_SHA256_ALGORITHM;
    case 384: return BCRYPT_SHA384_ALGORITHM;
    case 512: return BCRYPT_SHA512_ALGORITHM;
    default: return NULL;
  }
}

static void execute_windows(key_call* call) {
  NCRYPT_KEY_HANDLE handle = call->key->handle;
  DWORD size = 0;
  SECURITY_STATUS status;
  if (!call->decrypt) {
    BCRYPT_PKCS1_PADDING_INFO pkcs1;
    BCRYPT_PSS_PADDING_INFO pss;
    void* padding_info = NULL;
    DWORD flags = NCRYPT_SILENT_FLAG;
    if (call->padding == 1) {
      pkcs1.pszAlgId = cng_hash(call->hash);
      padding_info = &pkcs1;
      flags |= BCRYPT_PAD_PKCS1;
    } else if (call->padding == 2) {
      pss.pszAlgId = cng_hash(call->hash);
      pss.cbSalt = (ULONG)call->salt_length;
      padding_info = &pss;
      flags |= BCRYPT_PAD_PSS;
    }
    status = NCryptSignHash(handle, padding_info, call->input, (DWORD)call->input_length, NULL, 0, &size, flags);
    if (status == ERROR_SUCCESS) {
      call->output_capacity = size == 0 ? 1 : size;
      call->output = malloc(call->output_capacity);
      if (call->output == NULL) {
        status = NTE_NO_MEMORY;
      } else {
        status = NCryptSignHash(handle, padding_info, call->input, (DWORD)call->input_length, call->output, size, &size, flags);
      }
    }
    if (status != ERROR_SUCCESS) {
      call->status = (double)(uint32_t)status;
      snprintf(call->message, sizeof call->message, "NCryptSignHash failed with status 0x%08X.", (unsigned)status);
      return;
    }
  } else {
    BCRYPT_OAEP_PADDING_INFO oaep;
    void* padding_info = NULL;
    DWORD flags = NCRYPT_SILENT_FLAG;
    if (call->padding == 2) {
      oaep.pszAlgId = cng_hash(call->hash);
      oaep.pbLabel = call->label_length > 0 ? call->label : NULL;
      oaep.cbLabel = (ULONG)call->label_length;
      padding_info = &oaep;
      flags |= NCRYPT_PAD_OAEP_FLAG;
    } else {
      flags |= NCRYPT_PAD_PKCS1_FLAG;
    }
    status = NCryptDecrypt(handle, call->input, (DWORD)call->input_length, padding_info, NULL, 0, &size, flags);
    if (status == ERROR_SUCCESS) {
      call->output_capacity = size == 0 ? 1 : size;
      call->output = malloc(call->output_capacity);
      if (call->output == NULL) {
        status = NTE_NO_MEMORY;
      } else {
        status = NCryptDecrypt(handle, call->input, (DWORD)call->input_length, padding_info, call->output, size, &size, flags);
      }
    }
    if (status != ERROR_SUCCESS) {
      call->status = (double)(uint32_t)status;
      snprintf(call->message, sizeof call->message, "NCryptDecrypt failed with status 0x%08X.", (unsigned)status);
      return;
    }
  }
  call->output_length = size;
}
#endif

#if defined(__APPLE__)
/* The SecKeyAlgorithm each number TypeScript passes names. */
static SecKeyAlgorithm mac_algorithm(int32_t algorithm) {
  switch (algorithm) {
    case 11: return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1;
    case 12: return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224;
    case 13: return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
    case 14: return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384;
    case 15: return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512;
    case 21: return kSecKeyAlgorithmRSASignatureDigestPSSSHA1;
    case 22: return kSecKeyAlgorithmRSASignatureDigestPSSSHA224;
    case 23: return kSecKeyAlgorithmRSASignatureDigestPSSSHA256;
    case 24: return kSecKeyAlgorithmRSASignatureDigestPSSSHA384;
    case 25: return kSecKeyAlgorithmRSASignatureDigestPSSSHA512;
    case 31: return kSecKeyAlgorithmECDSASignatureDigestX962SHA1;
    case 32: return kSecKeyAlgorithmECDSASignatureDigestX962SHA224;
    case 33: return kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
    case 34: return kSecKeyAlgorithmECDSASignatureDigestX962SHA384;
    case 35: return kSecKeyAlgorithmECDSASignatureDigestX962SHA512;
    case 41: return kSecKeyAlgorithmRSAEncryptionPKCS1;
    case 51: return kSecKeyAlgorithmRSAEncryptionOAEPSHA1;
    case 52: return kSecKeyAlgorithmRSAEncryptionOAEPSHA224;
    case 53: return kSecKeyAlgorithmRSAEncryptionOAEPSHA256;
    case 54: return kSecKeyAlgorithmRSAEncryptionOAEPSHA384;
    case 55: return kSecKeyAlgorithmRSAEncryptionOAEPSHA512;
    default: return NULL;
  }
}

static void cf_string_into(CFStringRef text, char* out, size_t capacity) {
  out[0] = 0;
  if (text != NULL) CFStringGetCString(text, out, (CFIndex)capacity, kCFStringEncodingUTF8);
}

static void execute_mac(key_call* call) {
  SecKeyAlgorithm algorithm = mac_algorithm(call->algorithm);
  CFDataRef input = CFDataCreate(NULL, call->input, (CFIndex)call->input_length);
  if (input == NULL) {
    call->status = errSecAllocate;
    snprintf(call->message, sizeof call->message, "CFDataCreate failed.");
    return;
  }
  CFErrorRef error = NULL;
  CFDataRef result = call->decrypt ? SecKeyCreateDecryptedData(call->key->key, algorithm, input, &error)
                                   : SecKeyCreateSignature(call->key->key, algorithm, input, &error);
  CFRelease(input);
  if (result == NULL) {
    long code = errSecInternalComponent;
    char description[200];
    description[0] = 0;
    if (error != NULL) {
      code = (long)CFErrorGetCode(error);
      CFStringRef text = CFErrorCopyDescription(error);
      cf_string_into(text, description, sizeof description);
      if (text != NULL) CFRelease(text);
      CFRelease(error);
    }
    call->status = code == 0 ? (double)errSecInternalComponent : (double)code;
    snprintf(call->message, sizeof call->message, "%s failed (%ld): %s", call->decrypt ? "SecKeyCreateDecryptedData" : "SecKeyCreateSignature",
             code, description);
    return;
  }
  size_t length = (size_t)CFDataGetLength(result);
  call->output_capacity = length == 0 ? 1 : length;
  call->output = malloc(call->output_capacity);
  if (call->output == NULL) {
    call->status = errSecAllocate;
    snprintf(call->message, sizeof call->message, "out of memory");
  } else {
    if (length > 0) memcpy(call->output, CFDataGetBytePtr(result), length);
    call->output_length = length;
  }
  if (call->decrypt && length > 0) {
    /* The plaintext the framework made for this call alone: zeroed before it is released. */
    wipe((void*)CFDataGetBytePtr(result), length);
  }
  CFRelease(result);
}
#endif

static void execute_call(napi_env env, void* data) {
  (void)env;
  key_call* call = data;
#if defined(_WIN32)
  execute_windows(call);
#elif defined(__APPLE__)
  execute_mac(call);
#else
  call->status = -1;
  snprintf(call->message, sizeof call->message, "no key store on this platform");
#endif
}

static void complete_call(napi_env env, napi_status status, void* data) {
  key_call* call = data;
  os_key* key = call->key;
  if (status != napi_ok) {
    napi_reject_deferred(env, call->deferred, status_error(env, "The operation was cancelled.", -1));
  } else if (call->status != 0) {
    napi_reject_deferred(env, call->deferred, status_error(env, call->message, call->status));
  } else {
    napi_value result = js_buffer_copy(env, call->output, call->output_length);
    if (result == NULL) {
      napi_reject_deferred(env, call->deferred, status_error(env, "napi_create_buffer_copy failed", -1));
    } else {
      napi_resolve_deferred(env, call->deferred, result);
    }
  }
  key->inflight--;
  if (key->closed && key->inflight == 0) close_key_handle(key);
  napi_delete_reference(env, call->key_ref);
  napi_delete_async_work(env, call->work);
  free_call(call);
}

/* Queues call on the thread pool, returning its promise; frees it (and throws) on failure. */
static napi_value queue_call(napi_env env, napi_value key_value, key_call* call, const char* name) {
  napi_value promise, resource_name;
  if (call->key->closed) {
    free_call(call);
    napi_throw_error(env, "ERR_HKDFGUARD_CLOSED", "The certificate has been closed.");
    return NULL;
  }
  if (napi_create_promise(env, &call->deferred, &promise) != napi_ok
      || napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &resource_name) != napi_ok
      || napi_create_reference(env, key_value, 1, &call->key_ref) != napi_ok) {
    free_call(call);
    napi_throw_error(env, NULL, "hkdfguard_certificate: could not start the operation");
    return NULL;
  }
  if (napi_create_async_work(env, NULL, resource_name, execute_call, complete_call, call, &call->work) != napi_ok
      || napi_queue_async_work(env, call->work) != napi_ok) {
    napi_delete_reference(env, call->key_ref);
    free_call(call);
    napi_throw_error(env, NULL, "hkdfguard_certificate: could not queue the operation");
    return NULL;
  }
  call->key->inflight++;
  return promise;
}

static key_call* new_call(napi_env env, os_key* key, int decrypt) {
  key_call* call = calloc(1, sizeof(key_call));
  if (call == NULL) {
    napi_throw_error(env, NULL, "hkdfguard_certificate: out of memory");
    return NULL;
  }
  call->key = key;
  call->decrypt = decrypt;
  return call;
}
#endif /* _WIN32 || __APPLE__ */

/* --- Windows ------------------------------------------------------------------------------------- */

#if defined(_WIN32)
typedef struct windows_certificate {
  PCCERT_CONTEXT context;
} windows_certificate;

static void finalize_certificate(napi_env env, void* data, void* hint) {
  (void)env;
  (void)hint;
  windows_certificate* certificate = data;
  if (certificate->context != NULL) CertFreeCertificateContext(certificate->context);
  free(certificate);
}

static windows_certificate* certificate_arg(napi_env env, napi_value value) {
  void* data = NULL;
  if (napi_get_value_external(env, value, &data) != napi_ok || data == NULL) {
    napi_throw_type_error(env, NULL, "hkdfguard_certificate: expected a certificate handle");
    return NULL;
  }
  return data;
}

static int has_property(PCCERT_CONTEXT context, DWORD property) {
  DWORD size = 0;
  return CertGetCertificateContextProperty(context, property, NULL, &size) ? 1 : 0;
}

/* A UTF-8 JS string as a new UTF-16 string; free() it. NULL, with an exception pending, on failure. */
static wchar_t* wide_arg(napi_env env, napi_value value) {
  size_t length;
  if (napi_get_value_string_utf8(env, value, NULL, 0, &length) != napi_ok) {
    napi_throw_type_error(env, NULL, "hkdfguard_certificate: expected a string");
    return NULL;
  }
  char* utf8 = malloc(length + 1);
  if (utf8 == NULL) {
    napi_throw_error(env, NULL, "hkdfguard_certificate: out of memory");
    return NULL;
  }
  napi_get_value_string_utf8(env, value, utf8, length + 1, &length);
  if (strlen(utf8) != length || length > 256) {
    free(utf8);
    napi_throw_type_error(env, NULL, "hkdfguard_certificate: a store name contains NUL or is too long");
    return NULL;
  }
  int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, NULL, 0);
  wchar_t* wide = count > 0 ? malloc((size_t)count * sizeof(wchar_t)) : NULL;
  if (wide == NULL || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, wide, count) != count) {
    free(wide);
    free(utf8);
    napi_throw_error(env, NULL, "hkdfguard_certificate: invalid store name");
    return NULL;
  }
  free(utf8);
  return wide;
}

/* windowsReadStore(location, name): [{ der, hasPrivateKey, handle }], or null when the store can't
 * be opened. location is 1 for CurrentUser, 2 for LocalMachine. */
static napi_value windows_read_store(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  int32_t location;
  if (!int_arg(env, argv[0], &location)) return NULL;
  if (location != 1 && location != 2) {
    napi_throw_range_error(env, NULL, "hkdfguard_certificate: the store location is 1 or 2");
    return NULL;
  }
  wchar_t* name = wide_arg(env, argv[1]);
  if (name == NULL) return NULL;

  DWORD flags = CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG
                | (location == 1 ? CERT_SYSTEM_STORE_CURRENT_USER : CERT_SYSTEM_STORE_LOCAL_MACHINE);
  HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, flags, name);
  free(name);
  if (store == NULL) return js_null(env);

  napi_value result;
  if (napi_create_array(env, &result) != napi_ok) {
    CertCloseStore(store, 0);
    napi_throw_error(env, NULL, "hkdfguard_certificate: napi_create_array failed");
    return NULL;
  }
  uint32_t index = 0;
  PCCERT_CONTEXT context = NULL;
  DWORD error = 0;
  for (;;) {
    /* Frees the previous context and gives the next, or NULL - CRYPT_E_NOT_FOUND - after the last. */
    context = CertEnumCertificatesInStore(store, context);
    if (context == NULL) {
      error = GetLastError();
      break;
    }
    windows_certificate* certificate = malloc(sizeof(windows_certificate));
    if (certificate == NULL) {
      error = ERROR_NOT_ENOUGH_MEMORY;
      CertFreeCertificateContext(context);
      break;
    }
    certificate->context = CertDuplicateCertificateContext(context);
    /* What .NET's HasPrivateKey reads: a key provider's name and container, a key handle already
     * acquired, or a CNG key handle. */
    int has_key = has_property(context, CERT_KEY_PROV_INFO_PROP_ID) || has_property(context, CERT_KEY_CONTEXT_PROP_ID)
                  || has_property(context, CERT_NCRYPT_KEY_HANDLE_PROP_ID);
    napi_value entry, handle, der;
    der = js_buffer_copy(env, context->pbCertEncoded, context->cbCertEncoded);
    if (napi_create_external(env, certificate, finalize_certificate, NULL, &handle) != napi_ok) {
      CertFreeCertificateContext(certificate->context);
      free(certificate);
      error = ERROR_NOT_ENOUGH_MEMORY;
      CertFreeCertificateContext(context);
      break;
    }
    if (der == NULL || napi_create_object(env, &entry) != napi_ok) {
      error = ERROR_NOT_ENOUGH_MEMORY; /* the external's finalizer frees the duplicate */
      CertFreeCertificateContext(context);
      break;
    }
    napi_set_named_property(env, entry, "der", der);
    napi_set_named_property(env, entry, "hasPrivateKey", js_boolean(env, has_key));
    napi_set_named_property(env, entry, "handle", handle);
    napi_set_element(env, result, index++, entry);
  }
  /* Each certificate kept is a duplicated context, which holds the store's memory until it is freed. */
  CertCloseStore(store, 0);
  if (error != (DWORD)CRYPT_E_NOT_FOUND && error != ERROR_NO_MORE_FILES && error != 0) {
    char message[128];
    snprintf(message, sizeof message, "Reading the certificate store failed with error 0x%08X.", (unsigned)error);
    napi_throw(env, status_error(env, message, (double)error));
    return NULL;
  }
  return result;
}

/* windowsFreeCertificate(handle): frees the certificate's context now. */
static napi_value windows_free_certificate(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  windows_certificate* certificate = certificate_arg(env, argv[0]);
  if (certificate == NULL) return NULL;
  if (certificate->context != NULL) CertFreeCertificateContext(certificate->context);
  certificate->context = NULL;
  return js_undefined(env);
}

/* windowsOpenKey(handle): a key handle, or { error: 'acquire', status } when CNG can't open the key
 * silently, or { error: 'not-cng' } for a key only a CryptoAPI provider holds. */
static napi_value windows_open_key(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  windows_certificate* certificate = certificate_arg(env, argv[0]);
  if (certificate == NULL) return NULL;
  if (certificate->context == NULL) {
    napi_throw_error(env, "ERR_HKDFGUARD_CLOSED", "The certificate has been closed.");
    return NULL;
  }
  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE handle = 0;
  DWORD spec = 0;
  BOOL caller_free = FALSE;
  napi_value result;
  if (!CryptAcquireCertificatePrivateKey(certificate->context, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL,
                                         &handle, &spec, &caller_free)) {
    DWORD error = GetLastError();
    CHECK(napi_create_object(env, &result));
    napi_set_named_property(env, result, "error", js_string(env, "acquire"));
    napi_set_named_property(env, result, "status", js_number(env, (double)error));
    return result;
  }
  if (spec != CERT_NCRYPT_KEY_SPEC) {
    /* Not a CNG key, despite the flag: a CryptoAPI provider handle, which this never uses. */
    if (caller_free && handle != 0) CryptReleaseContext((HCRYPTPROV)handle, 0);
    CHECK(napi_create_object(env, &result));
    napi_set_named_property(env, result, "error", js_string(env, "not-cng"));
    return result;
  }
  os_key* key = calloc(1, sizeof(os_key));
  if (key == NULL) {
    if (caller_free) NCryptFreeObject((NCRYPT_KEY_HANDLE)handle);
    napi_throw_error(env, NULL, "hkdfguard_certificate: out of memory");
    return NULL;
  }
  key->handle = (NCRYPT_KEY_HANDLE)handle;
  key->owned = caller_free ? 1 : 0;
  key->context = CertDuplicateCertificateContext(certificate->context);
  return wrap_key(env, key);
}

/* windowsSign(key, digest, hash, padding, saltLength): the signature. hash is 1, 256, 384 or 512 (SHA-1
 * or SHA-2); padding 0 for ECDSA (no padding info: CNG signs the digest as IEEE P1363 r||s), 1 for RSA
 * PKCS #1 v1.5, 2 for RSA PSS with MGF1 over the same hash and saltLength bytes of salt. */
static napi_value windows_sign(napi_env env, napi_callback_info info) {
  size_t argc = 5;
  napi_value argv[5];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  os_key* key = key_arg(env, argv[0]);
  if (key == NULL) return NULL;
  key_call* call = new_call(env, key, 0);
  if (call == NULL) return NULL;
  if (!int_arg(env, argv[2], &call->hash) || !int_arg(env, argv[3], &call->padding) || !int_arg(env, argv[4], &call->salt_length)) {
    free_call(call);
    return NULL;
  }
  if ((call->padding != 0 && cng_hash(call->hash) == NULL) || call->padding < 0 || call->padding > 2 || call->salt_length < 0) {
    free_call(call);
    napi_throw_range_error(env, NULL, "hkdfguard_certificate: an unsupported hash, padding or salt length");
    return NULL;
  }
  call->input = bytes_copy_arg(env, argv[1], &call->input_length);
  if (call->input == NULL) {
    free_call(call);
    return NULL;
  }
  return queue_call(env, argv[0], call, "hkdfguard_certificate.windowsSign");
}

/* windowsDecrypt(key, ciphertext, padding, hash, label): the plaintext. padding 1 for PKCS #1 v1.5,
 * 2 for OAEP with MGF1 over hash and label (a Uint8Array, maybe empty). */
static napi_value windows_decrypt(napi_env env, napi_callback_info info) {
  size_t argc = 5;
  napi_value argv[5];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  os_key* key = key_arg(env, argv[0]);
  if (key == NULL) return NULL;
  key_call* call = new_call(env, key, 1);
  if (call == NULL) return NULL;
  if (!int_arg(env, argv[2], &call->padding) || !int_arg(env, argv[3], &call->hash)) {
    free_call(call);
    return NULL;
  }
  if ((call->padding != 1 && call->padding != 2) || (call->padding == 2 && cng_hash(call->hash) == NULL)) {
    free_call(call);
    napi_throw_range_error(env, NULL, "hkdfguard_certificate: an unsupported padding or hash");
    return NULL;
  }
  call->input = bytes_copy_arg(env, argv[1], &call->input_length);
  if (call->input == NULL) {
    free_call(call);
    return NULL;
  }
  call->label = bytes_copy_arg(env, argv[4], &call->label_length);
  if (call->label == NULL) {
    free_call(call);
    return NULL;
  }
  return queue_call(env, argv[0], call, "hkdfguard_certificate.windowsDecrypt");
}
#endif /* _WIN32 */

/* --- macOS --------------------------------------------------------------------------------------- */

#if defined(__APPLE__)
/* The SecKeychain calls and types are deprecated, but are the only way to restrict a search to one
 * keychain, as the Go and Python ports do. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

typedef struct mac_identity {
  SecIdentityRef identity;
} mac_identity;

static void finalize_identity(napi_env env, void* data, void* hint) {
  (void)env;
  (void)hint;
  mac_identity* identity = data;
  if (identity->identity != NULL) CFRelease(identity->identity);
  free(identity);
}

static mac_identity* identity_arg(napi_env env, napi_value value) {
  void* data = NULL;
  if (napi_get_value_external(env, value, &data) != napi_ok || data == NULL) {
    napi_throw_type_error(env, NULL, "hkdfguard_certificate: expected an identity handle");
    return NULL;
  }
  return data;
}

static void status_message(OSStatus status, char* out, size_t capacity) {
  CFStringRef text = SecCopyErrorMessageString(status, NULL);
  char description[160];
  cf_string_into(text, description, sizeof description);
  if (text != NULL) CFRelease(text);
  snprintf(out, capacity, "OSStatus %d%s%s", (int)status, description[0] ? ": " : "", description);
}

static napi_value throw_status(napi_env env, const char* what, OSStatus status) {
  char message[256], detail[200];
  status_message(status, detail, sizeof detail);
  snprintf(message, sizeof message, "%s failed: %s.", what, detail);
  napi_throw(env, status_error(env, message, (double)status));
  return NULL;
}

/* The DER of a certificate, or of an identity's certificate, as a new Buffer; NULL if it has none. */
static napi_value certificate_der(napi_env env, CFTypeRef item, int identity) {
  SecCertificateRef certificate = NULL;
  if (identity) {
    if (SecIdentityCopyCertificate((SecIdentityRef)item, &certificate) != errSecSuccess) return NULL;
  } else {
    certificate = (SecCertificateRef)item;
    CFRetain(certificate);
  }
  CFDataRef data = SecCertificateCopyData(certificate);
  CFRelease(certificate);
  if (data == NULL) return NULL;
  napi_value der = js_buffer_copy(env, CFDataGetBytePtr(data), (size_t)CFDataGetLength(data));
  CFRelease(data);
  return der;
}

/* Every item of one class in that keychain alone, as a CFArray the caller releases; *out NULL for none. */
static OSStatus copy_items(SecKeychainRef keychain, int identities, CFArrayRef* out) {
  *out = NULL;
  const void* search_items[1];
  search_items[0] = keychain;
  CFArrayRef search_list = CFArrayCreate(NULL, search_items, 1, &kCFTypeArrayCallBacks);
  if (search_list == NULL) return errSecAllocate;
  const void* keys[4];
  const void* values[4];
  keys[0] = kSecClass;
  values[0] = identities ? kSecClassIdentity : kSecClassCertificate;
  keys[1] = kSecMatchSearchList;
  values[1] = search_list;
  keys[2] = kSecMatchLimit;
  values[2] = kSecMatchLimitAll;
  keys[3] = kSecReturnRef;
  values[3] = kCFBooleanTrue;
  CFDictionaryRef query = CFDictionaryCreate(NULL, keys, values, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFRelease(search_list);
  if (query == NULL) return errSecAllocate;
  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching(query, &result);
  CFRelease(query);
  if (status == errSecItemNotFound) return errSecSuccess;
  if (status != errSecSuccess) return status;
  if (result == NULL || CFGetTypeID(result) != CFArrayGetTypeID()) {
    if (result != NULL) CFRelease(result);
    return errSecInternalComponent;
  }
  *out = (CFArrayRef)result;
  return errSecSuccess;
}

/* macReadKeychain(location): { identities: [{ der, handle }], certificates: [der] }, or null when the
 * keychain doesn't exist. location is 1 for CurrentUser (the effective user's login keychain), 2 for
 * LocalMachine (the System keychain). The certificates may repeat the identities' certificates. */
static napi_value mac_read_keychain(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  int32_t location;
  if (!int_arg(env, argv[0], &location)) return NULL;
  char path[1024];
  if (location == 2) {
    snprintf(path, sizeof path, "/Library/Keychains/System.keychain");
  } else if (location == 1) {
    struct passwd entry;
    struct passwd* found = NULL;
    char buffer[4096];
    int error = getpwuid_r(geteuid(), &entry, buffer, sizeof buffer, &found);
    if (error != 0 || found == NULL || found->pw_dir == NULL || found->pw_dir[0] != '/') {
      napi_throw_error(env, NULL, "The effective user has no home folder in the account database, so no login keychain.");
      return NULL;
    }
    if (snprintf(path, sizeof path, "%s/Library/Keychains/login.keychain-db", found->pw_dir) >= (int)sizeof path) {
      napi_throw_error(env, NULL, "The login keychain's path is too long.");
      return NULL;
    }
  } else {
    napi_throw_range_error(env, NULL, "hkdfguard_certificate: the keychain location is 1 or 2");
    return NULL;
  }

  SecKeychainRef keychain = NULL;
  OSStatus status = SecKeychainOpen(path, &keychain);
  if (status != errSecSuccess) return throw_status(env, "Opening the keychain", status);
  SecKeychainStatus keychain_status = 0;
  status = SecKeychainGetStatus(keychain, &keychain_status);
  if (status == errSecNoSuchKeychain) {
    CFRelease(keychain);
    return js_null(env);
  }
  if (status != errSecSuccess) {
    CFRelease(keychain);
    return throw_status(env, "Opening the keychain", status);
  }

  napi_value result, identities, certificates;
  if (napi_create_object(env, &result) != napi_ok || napi_create_array(env, &identities) != napi_ok
      || napi_create_array(env, &certificates) != napi_ok) {
    CFRelease(keychain);
    napi_throw_error(env, NULL, "hkdfguard_certificate: could not create the result");
    return NULL;
  }
  for (int pass = 0; pass < 2; pass++) {
    int identity = pass == 0;
    CFArrayRef items = NULL;
    status = copy_items(keychain, identity, &items);
    if (status != errSecSuccess) {
      CFRelease(keychain);
      return throw_status(env, "Searching the keychain", status);
    }
    if (items == NULL) continue;
    uint32_t index = 0;
    CFIndex count = CFArrayGetCount(items);
    for (CFIndex i = 0; i < count; i++) {
      CFTypeRef item = CFArrayGetValueAtIndex(items, i);
      if (item == NULL) continue;
      napi_value der = certificate_der(env, item, identity);
      if (der == NULL) continue; /* no certificate to read: it can't be the one named */
      if (!identity) {
        napi_set_element(env, certificates, index++, der);
        continue;
      }
      mac_identity* held = malloc(sizeof(mac_identity));
      napi_value entry, handle;
      if (held == NULL) continue;
      held->identity = (SecIdentityRef)CFRetain(item);
      if (napi_create_external(env, held, finalize_identity, NULL, &handle) != napi_ok) {
        CFRelease(held->identity);
        free(held);
        continue;
      }
      if (napi_create_object(env, &entry) != napi_ok) continue; /* the finalizer releases the identity */
      napi_set_named_property(env, entry, "der", der);
      napi_set_named_property(env, entry, "handle", handle);
      napi_set_element(env, identities, index++, entry);
    }
    CFRelease(items);
  }
  CFRelease(keychain);
  napi_set_named_property(env, result, "identities", identities);
  napi_set_named_property(env, result, "certificates", certificates);
  return result;
}

/* macReleaseIdentity(identity): releases it now. */
static napi_value mac_release_identity(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  mac_identity* identity = identity_arg(env, argv[0]);
  if (identity == NULL) return NULL;
  if (identity->identity != NULL) CFRelease(identity->identity);
  identity->identity = NULL;
  return js_undefined(env);
}

/* macOpenKey(identity): a key handle, or { error: 'copy', status, message }. */
static napi_value mac_open_key(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  mac_identity* identity = identity_arg(env, argv[0]);
  if (identity == NULL) return NULL;
  if (identity->identity == NULL) {
    napi_throw_error(env, "ERR_HKDFGUARD_CLOSED", "The certificate has been closed.");
    return NULL;
  }
  SecKeyRef reference = NULL;
  OSStatus status = SecIdentityCopyPrivateKey(identity->identity, &reference);
  if (status != errSecSuccess || reference == NULL) {
    char message[200];
    napi_value result;
    status_message(status, message, sizeof message);
    CHECK(napi_create_object(env, &result));
    napi_set_named_property(env, result, "error", js_string(env, "copy"));
    napi_set_named_property(env, result, "status", js_number(env, (double)status));
    napi_set_named_property(env, result, "message", js_string(env, message));
    return result;
  }
  os_key* key = calloc(1, sizeof(os_key));
  if (key == NULL) {
    CFRelease(reference);
    napi_throw_error(env, NULL, "hkdfguard_certificate: out of memory");
    return NULL;
  }
  key->key = reference;
  return wrap_key(env, key);
}

/* macSign(key, digest, algorithm) and macDecrypt(key, ciphertext, algorithm): algorithm is one of
 * mac_algorithm's numbers; one the key doesn't support rejects with status -1 before anything runs. */
static napi_value mac_operation(napi_env env, napi_callback_info info, int decrypt) {
  size_t argc = 3;
  napi_value argv[3];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  os_key* key = key_arg(env, argv[0]);
  if (key == NULL) return NULL;
  key_call* call = new_call(env, key, decrypt);
  if (call == NULL) return NULL;
  if (!int_arg(env, argv[2], &call->algorithm)) {
    free_call(call);
    return NULL;
  }
  SecKeyAlgorithm algorithm = mac_algorithm(call->algorithm);
  int is_decryption = call->algorithm >= 41;
  if (algorithm == NULL || is_decryption != decrypt) {
    free_call(call);
    napi_throw_range_error(env, NULL, "hkdfguard_certificate: an unknown algorithm");
    return NULL;
  }
  if (!key->closed && key->key != NULL
      && !SecKeyIsAlgorithmSupported(key->key, decrypt ? kSecKeyOperationTypeDecrypt : kSecKeyOperationTypeSign, algorithm)) {
    free_call(call);
    napi_throw(env, status_error(env, "The keychain key doesn't support this algorithm.", -1));
    return NULL;
  }
  call->input = bytes_copy_arg(env, argv[1], &call->input_length);
  if (call->input == NULL) {
    free_call(call);
    return NULL;
  }
  return queue_call(env, argv[0], call, decrypt ? "hkdfguard_certificate.macDecrypt" : "hkdfguard_certificate.macSign");
}

static napi_value mac_sign(napi_env env, napi_callback_info info) { return mac_operation(env, info, 0); }
static napi_value mac_decrypt(napi_env env, napi_callback_info info) { return mac_operation(env, info, 1); }

#pragma clang diagnostic pop
#endif /* __APPLE__ */

/* --- Module -------------------------------------------------------------------------------------- */

NAPI_MODULE_INIT() {
#if defined(_WIN32) || defined(__APPLE__)
  napi_property_descriptor properties[] = {
    { "releaseKey", NULL, release_key, NULL, NULL, NULL, napi_enumerable, NULL },
#if defined(_WIN32)
    { "windowsReadStore", NULL, windows_read_store, NULL, NULL, NULL, napi_enumerable, NULL },
    { "windowsFreeCertificate", NULL, windows_free_certificate, NULL, NULL, NULL, napi_enumerable, NULL },
    { "windowsOpenKey", NULL, windows_open_key, NULL, NULL, NULL, napi_enumerable, NULL },
    { "windowsSign", NULL, windows_sign, NULL, NULL, NULL, napi_enumerable, NULL },
    { "windowsDecrypt", NULL, windows_decrypt, NULL, NULL, NULL, napi_enumerable, NULL },
#endif
#if defined(__APPLE__)
    { "macReadKeychain", NULL, mac_read_keychain, NULL, NULL, NULL, napi_enumerable, NULL },
    { "macReleaseIdentity", NULL, mac_release_identity, NULL, NULL, NULL, napi_enumerable, NULL },
    { "macOpenKey", NULL, mac_open_key, NULL, NULL, NULL, napi_enumerable, NULL },
    { "macSign", NULL, mac_sign, NULL, NULL, NULL, napi_enumerable, NULL },
    { "macDecrypt", NULL, mac_decrypt, NULL, NULL, NULL, napi_enumerable, NULL },
#endif
  };
  if (napi_define_properties(env, exports, sizeof properties / sizeof properties[0], properties) != napi_ok) {
    return NULL;
  }
#else
  (void)env;
#endif
  return exports;
}
