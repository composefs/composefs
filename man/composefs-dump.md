% composefs-dump 5 "" composefs "User Commands"

# NAME

composefs-dump - textual file format for composefs content

# DESCRIPTION

Both the *composefs-info* and the *mkcompose* commands support
generation/consumptions of a textual descriptions of the contents of a
composefs image. This can be used to inspect or modify an image, or to
generate an image without having to have a local directory with the
files in it.

The file format is very simple, with one file per line, first with a
11 fixed fields, followed by a variable number of extended attributes
for the file. It is recommended, but not required to include a trailing
newline for the last file.

Fields are separated by a single space, and lines by a single
newline. Extended attributes further use '=' to separate key from
value. Therefore all these characters, as well as non-printable
characters are escaped in the fields ('=' only in xattr fields).
Also, back-slashes have to be escaped as they are used as the
escape mechanism.

Escapes are of the form \xXY which escapes a single byte using two hex
digits. For example \x00 is the zero byte and \xff is the 255 byte.
Optionally, these custom escapes are supported:

 **\\\\**
 :    backslash.

 **\\n**
 :    newline.

 **\\r**
 :    carriage return.

 **\\t**
 :    tab


Optional fields that are not set contain '-', and if a field actually
has that particular value it is escaped.

The fixed fields on a line are (all numbers in base 10 unless
otherwise specified):

**PATH**
:   The full, absolute path of the file in the image. Any directories
    used as prefix in the path must have been in the file before this
    line.

**SIZE**
:   The size of the file. This is ignored for directories.

**MODE**
:    The st_mode stat field the file in octal, which includes both the
     permissions and the file type.

     Additionally, if the file is a hardlink, then this field will
     start with a single '@' character, and the payload field points
     to the target file. Note that all other fields are typically
     filled out for a hardlink as the target, but for generation
     of a new file we ignore all the fields except the payload.

**NLINK**
:    The st_nlink stat field.

**UID**
:    The owner uid.

**GID**
:    The owner gid.

**RDEV**
:    The st_rdev stat field.

**MTIME**
:    The modification time in seconds and nanoseconds since the unix
     epoch, separated by '.'. Note this is not a float, "1.1" means
     one second and one nanosecond.

**PAYLOAD**
:   The payload of the file. For symbolic links this means the symlink
    targets. For regular files this is the relative pathname for the
    backing files. For hardlinks (see **MODE**), this is the path of
    another file in this file that this is a hardlink of.

**CONTENT**
:   Small files can inline the actual content in the composefs
    image. This contains an escaped version of the content.
    This must match the size specified in **SIZE**

**DIGEST**
:   A fs-verity digest for the file (only used for regular files, and
    not if *CONTENT* is set) that will be validated against backing
    files when used.

After the fixed fields comes the xattrs, escaped and space-separated in the form
**KEY**=**VALUE**. Note that '=' must be escaped in **KEY**.


# EXAMPLE

```
/ 4096 40755 4 1000 1000 0 1695372970.944925700 - - - security.selinux=unconfined_u:object_r:unlabeled_t:s0\x00
/a\x20dir\x20w\x20space 27 40755 2 1000 1000 0 1694598852.869646118 - - - security.selinux=unconfined_u:object_r:unlabeled_t:s0\x00
/a-dir 45 40755 2 1000 1000 0 1674041780.601887980 - - - security.selinux=unconfined_u:object_r:unlabeled_t:s0\x00
/a-dir/a-file 259 100644 1 1000 1000 0 1695368732.385062094 35/d02f81325122d77ec1d11baba655bc9bf8a891ab26119a41c50fa03ddfb408 - 35d02f81325122d77ec1d11baba655bc9bf8a891ab26119a41c50fa03ddfb408 security.selinux=unconfined_u:object_r:unlabeled_t:s0\x00
/a-hardlink 259 @100644 1 1000 1000 0 1695368732.385062094 /a-dir/a-file - 35d02f81325122d77ec1d11baba655bc9bf8a891ab26119a41c50fa03ddfb408 security.selinux=unconfined_u:object_r:unlabeled_t:s0\x00
/inline.txt 10 100644 1 1000 1000 0 1697019909.446146440 - some-text\n - security.selinux=unconfined_u:object_r:unlabeled_t:s0\x00
```

# SEE ALSO

**composefs-info(1)**, **mkcomposefs(1)**

[composefs upstream](https://github.com/containers/composefs)
