{
  "targets": [
    {
      "target_name": "hkdfguard_native",
      "sources": ["native/hkdfguard_native.c"],
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
          "conditions": [["target_arch=='x64'", { "cflags": ["-fcf-protection=full"] }]],
          "link_settings": { "libraries": ["-ldl"] }
        }],
        ["OS=='win'", {
          "msvs_settings": {
            "VCCLCompilerTool": { "WarningLevel": 4, "WarnAsError": "true", "AdditionalOptions": ["/guard:cf"] },
            "VCLinkerTool": { "AdditionalOptions": ["/DEPENDENTLOADFLAG:0x800", "/guard:cf"] }
          },
          "link_settings": { "libraries": ["wintrust.lib", "crypt32.lib", "advapi32.lib", "shell32.lib", "ole32.lib", "version.lib"] }
        }]
      ]
    }
  ]
}
