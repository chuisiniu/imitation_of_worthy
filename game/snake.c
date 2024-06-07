#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "snake.h"
#include "memhook.h"

struct point *snake_next_head_point(struct snake *s, struct screen *sc)
{
	struct snake_body *head;
	int x;
	int y;

	head = list_first_entry(&s->body, struct snake_body, node);
	switch (s->dir) {
	case SNAKE_DIR_UP:
		x = head->point->x;
		y = head->point->y - 1;
		break;
	case SNAKE_DIR_DOWN:
		x = head->point->x;
		y = head->point->y + 1;
		break;
	case SNAKE_DIR_LEFT:
		x = head->point->x - 1;
		y = head->point->y;
		break;
	case SNAKE_DIR_RIGHT:
		x = head->point->x + 1;
		y = head->point->y;
		break;
	default:
		return NULL;
	}

	if (x < 0)
		x = x + sc->width(sc);

	if (y < 0)
		y = y + sc->height(sc);

	return sc->get_point(sc, x, y);
}

int snake_head_shape(struct snake *s)
{
	int head_shape[SNAKE_DIR_MAX] = {
		[SNAKE_DIR_UP] = SNAKE_POINT_HEAD_UP,
		[SNAKE_DIR_DOWN] = SNAKE_POINT_HEAD_DOWV,
		[SNAKE_DIR_LEFT] = SNAKE_POINT_HEAD_LEFT,
		[SNAKE_DIR_RIGHT] = SNAKE_POINT_HEAD_RIGHT
	};

	return head_shape[s->dir];
}

int snake_move(struct snake *s, struct screen *sc)
{
	struct snake_body *head;
	struct snake_body *tail;
	struct point *next_head_point;


	if (list_empty(&s->body))
		return -1;

	next_head_point = snake_next_head_point(s, sc);
	if (NULL == next_head_point)
		return -1;

	if (SNAKE_POINT_EMPTY == next_head_point->ch) {
		tail = list_last_entry(&s->body, struct snake_body, node);
		list_del(&tail->node);
		tail->point->ch = SNAKE_POINT_EMPTY;
		sc->change_point(sc, tail->point);

		head = list_first_entry_or_null(&s->body, struct snake_body,
			node);
		if (head) {
			head->point->ch = SNAKE_POINT_BODY;
			sc->change_point(sc, head->point);
		}

		tail->point = next_head_point;
		tail->point->ch = snake_head_shape(s);
		sc->change_point(sc, tail->point);
		list_add(&tail->node, &s->body);
	} else if (SNAKE_POINT_FOOD == next_head_point->ch) {
		head = list_first_entry(&s->body, struct snake_body, node);
		head->point->ch = SNAKE_POINT_BODY;
		sc->change_point(sc, head->point);

		head = mem_alloc(sizeof(*head));
		head->point = next_head_point;
		head->point->ch = snake_head_shape(s);
		sc->change_point(sc, head->point);
		list_add(&head->node, &s->body);
	} else {
		return -1;
	}

	return 0;
}

int snake_change_dir(struct snake *s, enum snake_dir dir)
{
	switch (s->dir) {
	case SNAKE_DIR_UP:
	case SNAKE_DIR_DOWN:
		if (SNAKE_DIR_LEFT == dir || SNAKE_DIR_RIGHT == dir)
			s->dir = dir;
		break;
	case SNAKE_DIR_LEFT:
	case SNAKE_DIR_RIGHT:
		if (SNAKE_DIR_UP == dir || SNAKE_DIR_DOWN == dir)
			s->dir = dir;
		break;
	default:
		return -1;
	}

	return 0;
}

int screen_generate_food(struct screen *s)
{
	int height;
	int width;
	int random_x;
	int random_y;
	int x;
	int y;
	struct point *point;

	height = s->height(s);
	width = s->width(s);

	random_x = rand() % width;
	random_y = rand() % height;

	for (x = random_x; x < width; x++) {
		for (y = random_y; y < height; y++) {
			point = s->get_point(s, x, y);

			if (SNAKE_POINT_EMPTY == point->ch)
				goto OUT;
		}
	}

	for (x = random_x - 1; x >= 0; x--) {
		for (y = random_y - 1; y >= 0; y--) {
			point = s->get_point(s, x, y);

			if (SNAKE_POINT_EMPTY == point->ch)
				goto OUT;
		}
	}

	return -1;
OUT:
	point->ch = SNAKE_POINT_FOOD;
	s->change_point(s, point);

	return 0;
}

struct snake *create_snake(struct screen *sc, int speed)
{
	struct snake *snake;
	struct snake_body *body;

	snake = mem_alloc(sizeof(*snake));
	if (NULL == snake)
		return NULL;

	body = mem_alloc(sizeof(*body));
	if (NULL == body) {
		mem_free(snake);

		return NULL;
	}

	snake->dir = SNAKE_DIR_UP;
	INIT_LIST_HEAD(&snake->body);
	snake->move_interval = speed;

	body->point = sc->get_point(sc, sc->height(sc) / 2, sc->width(sc) / 2);
	if (NULL == body->point) {
		mem_free(body);
		mem_free(snake);

		return NULL;
	}

	body->point->ch = snake_head_shape(snake);
	sc->change_point(sc, body->point);
	list_add(&body->node, &snake->body);

	return snake;
}

void destroy_snake(struct snake *snake)
{
	struct snake_body *body;
	struct snake_body *tmp;

	list_for_each_entry_safe(body, tmp, &snake->body, node) {
		list_del(&body->node);
		mem_free(body);
	}

	mem_free(snake);
}

long long get_millisecond()
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

#define SNAKE_INTERVAL 1000

void snake_main(struct screen *screen)
{
	struct snake *snake;
	long long now;
	long long last;
	int input;

	snake = create_snake(screen, SNAKE_INTERVAL);

	last = 0;
	while (1) {
		now = get_millisecond();
		if (now - last > snake->move_interval) {
			snake_move(snake, screen);
			last = now;
		}

		input = screen->get_input(screen);
		if (ERR == input) {
			usleep(10);

			continue;
		}

		switch (input) {
		case 'w':
		case 'W':
			snake_change_dir(snake, SNAKE_DIR_UP);
			break;
		case 's':
		case 'S':
			snake_change_dir(snake, SNAKE_DIR_DOWN);
			break;
		case 'a':
		case 'A':
			snake_change_dir(snake, SNAKE_DIR_RIGHT);
			break;
		case 'd':
		case 'D':
			snake_change_dir(snake, SNAKE_DIR_RIGHT);
			break;
		default:
			continue;;
		}
	}
OUT:
}