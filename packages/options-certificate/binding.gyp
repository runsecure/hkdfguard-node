{
  "targets": [
    {
      "target_name": "hkdfguard_certificate",
      "sources": ["native/hkdfguard_certificate.c"],
      "cflags": ["-Wall", "-Wextra", "-Werror", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2"],
      "conditions": [
        ["OS=='mac'", {
          "xcode_settings": {
            "OTHER_CFLAGS": ["-Wall", "-Wextra", "-Werror", "-fstack-protector-strong"],
            "MACOSX_DEPLOYMENT_TARGET": "13.0"
          },
          "link_settings": { "libraries": ["-framework CoreFoundation", "-framework Security"] }
        }],
        ["OS=='linux'", {
          "cflags": ["-fstack-clash-protection"],
          "ldflags": ["-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,noexecstack"],
          "conditions": [["target_arch=='x64'", { "cflags": ["-fcf-protection=full"] }]]
        }],
        ["OS=='win'", {
          "msvs_settings": {
            "VCCLCompilerTool": { "WarningLevel": 4, "WarnAsError": "true", "AdditionalOptions": ["/guard:cf"] },
            "VCLinkerTool": { "AdditionalOptions": ["/DEPENDENTLOADFLAG:0x800", "/guard:cf"] }
          },
          "link_settings": { "libraries": ["crypt32.lib", "ncrypt.lib"] }
        }]
      ]
    }
  ]
}
