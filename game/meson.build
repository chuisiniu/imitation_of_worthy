ncursor = dependency('ncurses', main: true, required: true)

game_src_list = ['snake.c', 'ncurses_screen.c']

executable('game',
           files(game_src_list),
           include_directories: global_inc,
           link_with: [basic_lib, event_lib],
           dependencies: [ncursor])