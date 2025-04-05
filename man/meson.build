# SPDX-License-Identifier: GPL-2.0-or-later OR Apache-2.0
manuals = {
    '1': [
        'mkcomposefs',
        'composefs-info',
    ],
    '5': [
        'composefs-dump',
    ],
    '8': [
        'mount.composefs',
    ],
}

foreach section, pages: manuals
  foreach page: pages
    output = page + '.' + section
    input = page + '.md'
    sectiondir = 'man' + section

    custom_target(
      output,
      command: [
          go_md2man,
          '-in', '@INPUT@',
          '-out', '@OUTPUT@',
      ],
      input: input,
      install: true,
      install_dir: get_option('mandir') / sectiondir,
      output: output,
    )
  endforeach
endforeach
