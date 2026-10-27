{
  "targets": [
    {
      "target_name": "hkdfguard_securefile",
      "sources": ["native/hkdfguard_securefile.c"],
      "cflags": ["-Wall", "-Wextra", "-Werror", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2"],
      "conditions": [
        ["OS=='win'", {
          "msvs_settings": {
            "VCCLCompilerTool": { "WarningLevel": 4, "WarnAsError": "true" },
            "VCLinkerTool": { "AdditionalOptions": ["/DEPENDENTLOADFLAG:0x800"] }
          },
          "link_settings": { "libraries": ["advapi32.lib"] }
        }]
      ]
    }
  ]
}
