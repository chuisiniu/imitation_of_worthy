/*
 * 字典树实现
 * */
#include <strings.h>
#include <stdio.h>
#include <assert.h>

#include "dictree.h"
#include "memhook.h"

struct dict_tree *dt_create(unsigned char min, unsigned char max)
{
	struct dict_tree *t;

	t = mem_alloc(sizeof(*t));
	if (NULL == t)
		return NULL;

	t->min = min;
	t->max = max;
	t->width = max - min;
	t->arr = NULL;

	return t;
}

static struct dt_node_arr *dt_find_arr(
	struct dt_node_arr *arr,
	const unsigned char *str,
	int len,
	int *final_index)
{
	struct dt_node *node;
	int last_char_index;

	*final_index = -1;
	if (NULL == arr || len <= 0)
		return NULL;

	last_char_index = len - 1;
	while (1) {
		*final_index += 1;
		if (*final_index == last_char_index)
			return arr;

		node = &arr->arr[str[*final_index]];
		if (NULL == node->next)
			return arr;

		arr = node->next;
	}

	return arr;
}

static void dt_str_2_match_str(
	struct dict_tree *tree,
	const unsigned  char *str,
	int len,
	unsigned char *match,
	int *match_len)
{
	for (*match_len = 0; *match_len < len; (*match_len) += 1) {
		// 有字符超出范围，在树中就一定找不到，没有必要转换了
		if (str[*match_len] < tree->min || str[*match_len] > tree->max)
			return;
		if (*match_len == DICTREE_MAX_DEPTH)
			return;

		match[*match_len] = str[*match_len] - tree->min;
	}
}

void *dt_find(struct dict_tree *tree, const unsigned char *str, int len,
              int *prefix_len)
{
	int final_index;
	unsigned char match_str[DICTREE_MAX_DEPTH];
	int match_len;
	struct dt_node_arr *arr;
	struct dt_node *node;

	*prefix_len = 0;
	if (NULL == tree->arr || len == 0 || NULL == str)
		return NULL;

	dt_str_2_match_str(tree, str, len, match_str, &match_len);
	if (match_len == 0)
		return NULL;


	/*
	 * 这里如果不想得到准确的prefix_len，match_len < len，则可以返回NULL
	 * */

	arr = dt_find_arr(tree->arr, match_str, match_len, &final_index);
	node = &arr->arr[match_str[final_index]];
	if (node->next || node->data)
		*prefix_len = final_index + 1;

	if (final_index < match_len - 1)
		return NULL;

	if (len != *prefix_len)
		return NULL;

	return node->data;
}

void *dt_find_insert(
	struct dict_tree *tree,
	const unsigned char *str,
	int len,
	void *data)
{
	int final_index;
	unsigned char match_str[DICTREE_MAX_DEPTH];
	int match_len;
	int last_char_index;
	struct dt_node_arr *arr;
	struct dt_node *node;
	size_t sz;

	if (len == 0 || NULL == str)
		return NULL;

	dt_str_2_match_str(tree, str, len, match_str, &match_len);
	if (match_len != len)
		return NULL;

	sz = sizeof(struct dt_node_arr) + sizeof(struct dt_node) * tree->width;
	if (NULL == tree->arr) {
		tree->arr = mem_alloc(sz);
		if (NULL == tree->arr)
			return NULL;

		bzero(tree->arr, sz);
	}

	arr = dt_find_arr(tree->arr, match_str, match_len, &final_index);
	last_char_index = match_len - 1;
	while(final_index < last_char_index) {
		node = &arr->arr[match_str[final_index]];

		assert(NULL == node->next);
		node->next = mem_alloc(sz);
		if (NULL == node->next)
			return NULL;
		bzero(node->next, sz);
		node->next->prev = arr;
		node->next->c = match_str[final_index];

		arr = node->next;

		final_index += 1;
	}

	node = &arr->arr[match_str[final_index]];
	if (NULL == node->data)
		node->data = data;

	return node->data;
}

static
void dt_clean_arr(struct dict_tree *tree, struct dt_node_arr *arr)
{
	int i;
	struct dt_node_arr *tmp;
	int reach_root;

	reach_root = 0;
	while (arr) {
		for (i = 0; i < tree->width; i++) {
			if (arr->arr[i].next || arr->arr[i].data)
				return;
		}

		if (arr->prev)
			arr->prev->arr[arr->c].next = NULL;
		else
			reach_root = 1;

		tmp = arr->prev;
		mem_free(arr);

		arr = tmp;
	}

	if (reach_root)
		tree->arr = NULL;
}

void *dt_rm(struct dict_tree *tree, const unsigned char *str, int len)
{
	int final_index;
	unsigned char match_str[DICTREE_MAX_DEPTH];
	int match_len;
	struct dt_node_arr *arr;
	struct dt_node *node;
	void *data;

	if (len == 0 || NULL == str || NULL == tree->arr)
		return NULL;

	dt_str_2_match_str(tree, str, len, match_str, &match_len);
	if (match_len != len)
		return NULL;

	arr = dt_find_arr(tree->arr, match_str, match_len, &final_index);
	if (final_index < match_len - 1)
		return NULL;
	node = &arr->arr[match_str[final_index]];
	data = node->data;
	node->data = NULL;

	if (node->next)
		return data;

	dt_clean_arr(tree, arr);

	return data;
}

void dt_rm_all(struct dict_tree *tree,
               void (* release_data)(void *data))
{
	int c;
	struct dt_node *node;
	struct dt_node_arr *arr;
	struct dt_node_arr *tmp;

	arr = tree->arr;
	c = 0;
	while (arr) {
		node = &arr->arr[c];
		if (node->data && release_data)
			release_data(node->data);
		node->data = NULL;

		if (node->next) {
			arr = node->next;
			node->next = NULL;
			c = 0;

			continue;
		}

		c++;
		if (c == tree->width) {
			tmp = arr;
			arr = arr->prev;
			if (tmp == tree->arr)
				tree->arr = NULL;
			mem_free(tmp);

			c = 0;
		}
	}
}

char *dt_print_to_str(struct dict_tree *tree, char *dst, int len)
{
	unsigned char str[DICTREE_MAX_DEPTH + 1];
	int str_len;

	int c;
	struct dt_node *node;
	struct dt_node_arr *arr;

	int wlen;

	arr = tree->arr;
	c = 0;
	str_len = 0;
	wlen = 0;
	while (arr) {
		node = &arr->arr[c];
		str[str_len] = tree->min + c;

		if (node->data) {
			str[str_len + 1] = '\0';

			if (wlen >= len)
				return dst;

			wlen += snprintf(dst + wlen, len - wlen, "%s\n", str);
		}

		if (node->next) {
			str_len += 1;
			arr = node->next;
			c = 0;

			continue;
		}

		c++;
		while (c == tree->width) {
			arr = arr->prev;
			c = str[str_len - 1] - tree->min + 1;

			str_len -= 1;
		}
	}

	return dst;
}

static char dt_print_buf[4096];

void dt_print(struct dict_tree *tree)
{
	printf("%s", dt_print_to_str(tree, dt_print_buf, sizeof(dt_print_buf)));
}
