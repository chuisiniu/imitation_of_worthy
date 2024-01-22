#ifndef IMITATION_OF_WORTHY_DICTREE_H
#define IMITATION_OF_WORTHY_DICTREE_H

#define DICTREE_MAX_WIDTH  256
#define DICTREE_MAX_DEPTH  64

struct dt_node {
	void *data;
	struct dt_node_arr *next;
};

struct dt_node_arr {
	unsigned char c;
	struct dt_node_arr *prev;
	struct dt_node arr[0];
};

struct dict_tree {
	unsigned char min; // 树中的最小字符
	unsigned char max; // 树中的最大字符
	unsigned char width; // 树中个节点孩子的个数

	struct dt_node_arr *arr; // 第一层
};

struct dict_tree *dt_create(unsigned char min, unsigned char max);

void *dt_find(struct dict_tree *tree, const unsigned char *str, int len,
              int *prefix_len);
void *dt_find_insert(struct dict_tree *tree, const unsigned char *str, int len,
                     void *data);
void *dt_rm(struct dict_tree *tree, const unsigned char *str, int len);

void dt_print(struct dict_tree *tree);

static inline int dt_is_empty(struct dict_tree *t)
{
	return NULL == t->arr;
}

void dt_rm_all(struct dict_tree *tree,
               void (* release_data)(void *data));

#define DICT_TREE(_min, _max) {_min, _max, _max - _min + 1, NULL}

#endif //IMITATION_OF_WORTHY_DICTREE_H
