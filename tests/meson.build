test_assets_small = [
  'honggfuzz-write-inode-data.dump',
  'config.dump.gz',
  'config-with-hard-link.dump.gz',
  'special.dump',
  'longlink.dump',
  'bigfile.dump',
  'bigfile-xattr.dump',
  'special_v1.dump',
  'honggfuzz-long-symlink.dump',
  'honggfuzz-longlink-unterminated.dump',
  'honggfuzz-bigfile-with-acl.dump',
  'no-newline.dump',
  'honggfuzz-chardev-nonzero-size.dump',
]

test_assets_small_extra = [
  'special.dump.version',
  'special_v1.dump.version',
]

test_assets_should_fail = [
  'should-fail-long-link.dump',
  'should-fail-empty-xattr-key.dump',
  'should-fail-long-xattr-key.dump',
  'should-fail-long-xattr-value.dump',
  'should-fail-honggfuzz-long-xattr.dump',
  'should-fail-too-big.dump', 
  'should-fail-no-ftype.dump',
  'should-fail-empty-name.dump',
  'should-fail-empty-link-name.dump',
  'should-fail-dot-name.dump',
  'should-fail-dotdot-name.dump',
  'should-fail-dir-hardlink.dump',
  'should-fail-self-hardlink.dump',
  'should-fail-big-inline.dump',
]

test_assets = test_assets_small + [
  'cs9-x86_64-developer.dump.gz',
  'cs9-x86_64-minimal.dump.gz',
  'f36-x86_64-silverblue.dump.gz',
]

extra_dist = [
  'gendir',
  'dumpdir',
  'test-lib.sh',
  'test-units.sh',
  'test-random-fuse.sh',
  'test-checksums.sh',
  'test-dump-filtered.sh',
  'test-should-fail.sh',
  'integration.sh',
]

foreach asset : test_assets_should_fail
  extra_dist += ['assets/' + asset]
endforeach
foreach asset : test_assets_small_extra
  extra_dist += ['assets/' + asset]
endforeach
foreach asset : test_assets_small
  extra_dist += ['assets/' + asset, 'assets/' + asset + '.sha256']
endforeach

tools_dir = meson.current_build_dir() / '../tools'

test('check-units', find_program('test-units.sh'), args : [tools_dir])
test('check-checksums', find_program('test-checksums.sh'), args : [tools_dir, meson.current_source_dir() / 'assets', ' '.join(test_assets)], timeout : 300)
test('check-dump-filtered', find_program('test-dump-filtered.sh'), args : [tools_dir, meson.current_source_dir() / 'assets'])
test('check-random-fuse', find_program('test-random-fuse.sh'), args : [tools_dir], timeout : 300)
should_fail_args = [tools_dir]
foreach case : test_assets_should_fail
  should_fail_args += [meson.current_source_dir() / 'assets' / case]
endforeach
test('check-should-fail', find_program('test-should-fail.sh'), args : should_fail_args)

test('test-lcfs', executable('test-lcfs', 'test-lcfs.c', include_directories: '../libcomposefs', link_with: libcomposefs))

# support running the tests under valgrind using 'meson test -C build --setup=valgrind'
valgrind = find_program('valgrind', required : false)
if valgrind.found()
  add_test_setup('valgrind',
    exe_wrapper : [
      valgrind,
      '--quiet',
      '--leak-check=yes',
      '--error-exitcode=42',
    ],
    timeout_multiplier : 10,
  )
endif
