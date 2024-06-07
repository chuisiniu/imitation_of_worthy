#ifndef SNAKE_H
#define SNAKE_H
#include "linux/list.h"

#define SNAKE_MAX_WIDTH (4096)
#define SNAKE_MAX_HEIGHT (4096)

enum snake_dir {
	SNAKE_DIR_UP,
	SNAKE_DIR_DOWN,
	SNAKE_DIR_LEFT,
	SNAKE_DIR_RIGHT,

	SNAKE_DIR_MAX
};

#define SNAKE_POINT_EMPTY ' '
#define SNAKE_POINT_HEAD_LEFT '<'
#define SNAKE_POINT_HEAD_RIGHT '>'
#define SNAKE_POINT_HEAD_UP '^'
#define SNAKE_POINT_HEAD_DOWV 'v'
#define SNAKE_POINT_BODY '@'
#define SNAKE_POINT_FOOD '*'

struct point {
	int x;
	int y;

	int ch;
};

struct snake_body {
	struct point *point;

	struct list_head node;
};

struct snake {
	int dir;
	int len;
	int move_interval;

	struct list_head body;
};

struct screen {
	int width(struct screen *s);
	int height(struct screen *s);

	struct point *get_point(struct screen *s, int x, int y);
	int change_point(struct screen *s, struct point *point);

	long long get_input(struct screen *s);
};

#endif //SNAKE_H
