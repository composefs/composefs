% mount.composefs 8 "" composefs "User Commands"

# NAME

mount.composefs - mount a composefs filesystem image

# SYNOPSIS

**mount.composefs** [-o OPTIONS] *IMAGE* *TARGETDIR*

# DESCRIPTION

The composefs project uses EROFS image file to store metadata, and one
or more separate directories containing content-addressed backing data
for regular files.

**mount.composefs** mounts such an EROFS file in combination with a given
set of basedir at the specified location. It can be called directly, or
as a mount helper by running `mount -t composefs ...`.

# OPTIONS

The provided *IMAGE* argument must be a valid composefs (EROFS)
metadata image.  The *TARGETDIR* will be used as a mount target.

**mount.composefs** accepts the following colon-separated mount
options when passed via the `-o OPTIONS` argument.

**basedir**=*PATH*
:   This path will be used to resolve non-empty file references
    stored in the composefs metadata image.  A primary use case is to have
    this be the same path provided to `mkcomposefs --digest-store=PATH`.

    Multiple paths can be specified, separated by `:`.

**digest**=*DIGEST*
:   The image file is validated to have the specified fs-verity digest
    before being used. This allows a chain of trust the ensures only
    the expected data is ever visible in the mount.

    This option also implies **verity**.

**idmap**=*PATH*
:   Specify a path to a user namespace whose ID mapping should be used.
    The typical format for this type of path is `/proc/<pid>/ns/user`

**verity**
:   If this is specified, all files in the *IMAGE* must specify an fs-verity
    digest, and all the files in the base dirs must have a matching fs-verity
    digest.

    Note: This needs support for the overlayfs "verity" option in the
    kernel, which was added in 6.6rc1.

**ro**
:  Mounts the filesystem read-only. This is mainly useful when using
   **upperdir** as unlayered composefs images are naturally readonly.

**rw**
:  Overrides a previous **ro** option

**upperdir**
:  Specify an upper dir in the overlayfs mount that composefs uses. This allows
   a writable layer on top of the composefs image. See overlayfs docs for details.

**workdir**
:  Specifies an overlayfs workdir to go with **upperdir**.

# SEE ALSO

**composefs-info(1)**, **mount.composefs(1)**

[composefs upstream](https://github.com/containers/composefs)
