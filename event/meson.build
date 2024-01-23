event_src_list = ['event.c']

multipath = get_option('multipath_type')
if multipath == 'select'
	conf.set('EVENT_MULTIPATH_SELECT', 1)
	event_src_list += ['select_scheduler.c']
elif multipath == 'epoll'
	conf.set('EVENT_MULTIPATH_EPOLL', 1)
	event_src_list += ['epoll_scheduler.c']
endif

event_lib = library('event',
		files(event_src_list),
		include_directories: global_inc,
		link_with: basic_lib)
