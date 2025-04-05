% composefs-info 1 "" composefs "User Commands"

# NAME

composefs-info - print information about a composefs image

# SYNOPSIS
**composefs-info** [ls|objects|missing-objects|dump] *IMAGE* [*IMAGE2* *IMAGE3* ...]

# DESCRIPTION

The composefs-info command lets you inspect a composefs image. It has
several sub-commands:

**ls**
:   Prints a simple list of the files and directorie in the images as
    well as their backing file or symlink target.

**objects**
:   Prints a list of all the backing files referenced by the images,
    in sorted order.

**missing-objects**
:   Prints a list of all the missing backing files referenced by the
    images, in sorted order, given a backing file store passed in
    using the --basedir option.

**dump**
:   Prints a full dump of the images in a line based textual format.
    See **composefs-dump(5)** for more details. This format is also
    accepted as input to mkcomposefs if the --from-file
    option is used.

**measure-file**
:    Interpret the provided paths as generic files, and print their fsverity digest.

# OPTIONS

The provided *IMAGE* argument must be a composefs file. Multiple images
can be specified.

**compoosefs-info** accepts the following options:


**\-\-basedir**=*PATH*
:   This should point to a directory of backing files, and will be used
    by the **missing-objects** command to know what files are available.

**\-\-filter**=*NAME*
:   Only print entries whose name matches one of these. Can be specified
    multiple times. Cannot be a full path (e.g. cannot contain `/`).
    This is intended to be used for tooling to efficiently lookup metadata
    files embedded in the image without loading and printing the entire
    image.

# SEE ALSO
**composefs-info(1)**, **composefs-dump(5)**

[composefs upstream](https://github.com/containers/composefs)
