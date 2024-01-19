project('imitation_of_worthy', 'c')

conf = configuration_data()

if 'darwin' == build_machine.system() and 'aarch64' == build_machine.cpu()
    link_args = []
else
    link_args = ['-static']
endif

if get_option('use_memhook')
    conf.set('USE_MEMHOOK', 1)
endif

configure_file(
    output: 'config.h',
    configuration: conf)

global_inc = include_directories(
    'include',
    '.')

subdir('basic')
subdir('event')
subdir('echo_server')
subdir('test')
