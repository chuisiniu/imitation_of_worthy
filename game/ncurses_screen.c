#include <ncursesw/curses.h>

#include "memhook.h"
#include "snake.h"

struct ncurses_screen {
	struct screen interface;

	int width;
	int height;

	struct point points[0];
};

void init_ncurses()
{
	initscr();
	noecho();
	cbreak();
	nonl();

}

struct screen *create_ncurses_screen(int width, int height)
{
	struct ncurses_screen *ns;
	int max_points;

	max_points = width * height;
	ns = mem_alloc(sizeof(*ns) + max_points * sizeof(struct point));
	if (NULL == ns)
		return NULL;

	return &ns->interface;
}