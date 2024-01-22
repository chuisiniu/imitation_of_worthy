cunit_dep = dependency('cunit', main: true, required: false)

if cunit_dep.found()
    test_src = files(['test_main.c',
                      'test_rbtree.c',
                      'test_dictree.c',
                     ])
    e = executable('testprog', test_src, dependencies : cunit_dep,
                   link_with: basic_lib, include_directories: global_inc)
    test('test', e)
endif
