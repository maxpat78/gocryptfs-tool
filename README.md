# gocryptfs-tool

A simple Python3 script to access a gocryptfs filesystem and carry on some useful operations like:

```
ls       list virtual file system files and directories in decrypted form, with true size and times
decrypt  decrypt a file or directory into a given destination
alias    show the real pathname linked to a virtual one
backup   backup the Directory IVs (required to decrypt names) in a ZIP file
```

Passing a couple options, you can show you master key or recover it in case configuration files are corrupted:

`--print-key [a85 | b64]` shows the decrypted master key in ASCII85 or BASE64 form, to annotate it in a safe place for recovering purposes

`--master-key`  grants access to your files even in case of lost configuration file `gocryptfs.conf` , provided the master key in ASCII85 or BASE64 form
