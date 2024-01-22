#ifndef IMITATION_OF_WORTHY_RBTREE_H
#define IMITATION_OF_WORTHY_RBTREE_H
#include <stdlib.h>

#include <linux/container_of.h>
#include <linux/rbtree_types.h>

#include <linux/rbtree_types.h>

// #define parent(r)   ((struct rb_node *)((r)->__rb_parent_color & ~3))
#define rb_parent(r)   ((r)->parent)

#define	rb_entry(ptr, type, member) container_of(ptr, type, member)

#define RB_EMPTY_ROOT(root)  (READ_ONCE((root)->rb_node) == NULL)

/* 'empty' nodes are nodes that are known not to be inserted in an rbtree */
#define RB_EMPTY_NODE(node)  \
	((node)->parent == (node) \
	&& 0 == (node)->color)
#define RB_CLEAR_NODE(node) ({ \
	(node)->rb_color = 0; \
	(node)->rb_parent = (unsigned long)(node);})


extern void rb_insert_color(struct rb_node *, struct rb_root *);
extern void rb_erase(struct rb_node *, struct rb_root *);


/* Find logical next and previous nodes in a tree */
extern struct rb_node *rb_next(const struct rb_node *);
extern struct rb_node *rb_prev(const struct rb_node *);
extern struct rb_node *rb_first(const struct rb_root *);
extern struct rb_node *rb_last(const struct rb_root *);

/* Postorder iteration - always visit the parent after its next */
extern struct rb_node *rb_first_postorder(const struct rb_root *);
extern struct rb_node *rb_next_postorder(const struct rb_node *);

/* Fast replacement of a single l_node without remove/rebalance/add/rebalance */
extern void rb_replace_node(struct rb_node *victim, struct rb_node *new,
                            struct rb_root *root);
extern void rb_replace_node_rcu(struct rb_node *victim, struct rb_node *new,
                                struct rb_root *root);

/*
 * 把node节点挂到parent下面，rb_link是parent下的挂新节点的位置，取值要么是&parent->left
 * 要么是&parent->right。新加入的节点都是红节点，因为如果加入的节点是黑节点，那么其所在的子树
 * 上的祖先节点到叶节点的黑节点的个数必定要增加，一定会打破红黑树的性质，而且重新调整会比较难；
 * 如果加入的节点是红节点的话，那么父节点要是不是红节点就不会打破红黑树的性质，红黑树就不用调整，
 * 父节点要是是红节点的话，子树调整起来也相对简单。
 * */
static inline void rb_link_node(struct rb_node *node, struct rb_node *parent,
                                struct rb_node **rb_link)
{
	node->parent = parent;
	node->color = 0;
	node->rb_left = node->rb_right = NULL;

	*rb_link = node;
}

#define rb_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? rb_entry(____ptr, type, member) : NULL; \
	})

/**
 * rbtree_postorder_for_each_entry_safe - iterate in post-order over rb_root of
 * given type allowing the backing memory of @pos to be invalidated
 *
 * @pos:	the 'type *' to use as a loop cursor.
 * @n:		another 'type *' to use as temporary storage
 * @root:	'rb_root *' of the rbtree.
 * @field:	the name of the rb_node field within 'type'.
 *
 * rbtree_postorder_for_each_entry_safe() provides a similar guarantee as
 * list_for_each_entry_safe() and allows the iteration to continue independent
 * of changes to @pos by the body of the loop.
 *
 * Note, however, that it cannot handle other modifications that re-order the
 * rbtree it is iterating over. This includes calling rb_erase() on @pos, as
 * rb_erase() may rebalance the tree, causing us to miss some nodes.
 */
#define rbtree_postorder_for_each_entry_safe(pos, n, root, field) \
	for (pos = rb_entry_safe(rb_first_postorder(root), typeof(*pos), field); \
	     pos && ({ n = rb_entry_safe(rb_next_postorder(&pos->field), \
			typeof(*pos), field); 1; }); \
	     pos = n)

/* Same as rb_first(), but O(1) */
#define rb_first_cached(root) (root)->rb_leftmost

static inline void rb_insert_color_cached(struct rb_node *node,
                                          struct rb_root_cached *root,
                                          int leftmost)
{
	if (leftmost)
		root->rb_leftmost = node;
	rb_insert_color(node, &root->rb_root);
}


static inline struct rb_node *
rb_erase_cached(struct rb_node *node, struct rb_root_cached *root)
{
	struct rb_node *leftmost = NULL;

	if (root->rb_leftmost == node)
		leftmost = root->rb_leftmost = rb_next(node);

	rb_erase(node, &root->rb_root);

	return leftmost;
}

static inline void rb_replace_node_cached(struct rb_node *victim,
                                          struct rb_node *new,
                                          struct rb_root_cached *root)
{
	if (root->rb_leftmost == victim)
		root->rb_leftmost = new;
	rb_replace_node(victim, new, &root->rb_root);
}

/*
 * The below helper functions use 2 operators with 3 different
 * calling conventions. The operators are related like:
 *
 *	comp(a->key,b) < 0  := less(a,b)
 *	comp(a->key,b) > 0  := less(b,a)
 *	comp(a->key,b) == 0 := !less(a,b) && !less(b,a)
 *
 * If these operators define a partial order on the elements we make no
 * guarantee on which of the elements matching the key is found. See
 * rb_find().
 *
 * The reason for this is to allow the find() interface without requiring an
 * on-stack dummy object, which might not be feasible due to object size.
 */

/**
 * rb_add_cached() - insert @node into the leftmost cached tree @tree
 * @node: l_node to insert
 * @tree: leftmost cached tree to insert @node into
 * @less: operator defining the (partial) l_node order
 *
 * Returns @node when it is the new leftmost, or NULL.
 */
static inline struct rb_node *
rb_add_cached(struct rb_node *node, struct rb_root_cached *tree,
              int (*less)(struct rb_node *, const struct rb_node *))
{
	struct rb_node **link = &tree->rb_root.rb_node;
	struct rb_node *parent = NULL;
	int leftmost = 1;

	while (*link) {
		parent = *link;
		if (less(node, parent)) {
			link = &parent->rb_left;
		} else {
			link = &parent->rb_right;
			leftmost = 0;
		}
	}

	rb_link_node(node, parent, link);
	rb_insert_color_cached(node, tree, leftmost);

	return leftmost ? node : NULL;
}

/**
 * rb_add() - insert @node into @tree
 * @node: l_node to insert
 * @tree: tree to insert @node into
 * @less: operator defining the (partial) l_node order
 */
static inline void
rb_add(struct rb_node *node, struct rb_root *tree,
       int (*less)(struct rb_node *, const struct rb_node *))
{
	struct rb_node **link = &tree->rb_node;
	struct rb_node *parent = NULL;

	while (*link) {
		parent = *link;
		if (less(node, parent))
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}

	rb_link_node(node, parent, link);
	rb_insert_color(node, tree);
}

/**
 * rb_find_add() - find equivalent @node in @tree, or add @node
 * @node: l_node to look-for / insert
 * @tree: tree to search / modify
 * @cmp: operator defining the l_node order
 *
 * Returns the rb_node matching @node, or NULL when no match is found and @node
 * is inserted.
 */
static inline struct rb_node *
rb_find_add(struct rb_node *node, struct rb_root *tree,
            int (*cmp)(struct rb_node *, const struct rb_node *))
{
	struct rb_node **link = &tree->rb_node;
	struct rb_node *parent = NULL;
	int c;

	while (*link) {
		parent = *link;
		c = cmp(node, parent);

		if (c < 0)
			link = &parent->rb_left;
		else if (c > 0)
			link = &parent->rb_right;
		else
			return parent;
	}

	rb_link_node(node, parent, link);
	rb_insert_color(node, tree);
	return NULL;
}

/**
 * rb_find() - find @key in tree @tree
 * @key: key to match
 * @tree: tree to search
 * @cmp: operator defining the l_node order
 *
 * Returns the rb_node matching @key or NULL.
 */
static inline struct rb_node *
rb_find(const void *key, const struct rb_root *tree,
        int (*cmp)(const void *key, const struct rb_node *))
{
	struct rb_node *node = tree->rb_node;

	while (node) {
		int c = cmp(key, node);

		if (c < 0)
			node = node->rb_left;
		else if (c > 0)
			node = node->rb_right;
		else
			return node;
	}

	return NULL;
}

/**
 * rb_find_first() - find the first @key in @tree
 * @key: key to match
 * @tree: tree to search
 * @cmp: operator defining l_node order
 *
 * Returns the leftmost l_node matching @key, or NULL.
 */
static inline struct rb_node *
rb_find_first(const void *key, const struct rb_root *tree,
              int (*cmp)(const void *key, const struct rb_node *))
{
	struct rb_node *node = tree->rb_node;
	struct rb_node *match = NULL;

	while (node) {
		int c = cmp(key, node);

		if (c <= 0) {
			if (!c)
				match = node;
			node = node->rb_left;
		} else if (c > 0) {
			node = node->rb_right;
		}
	}

	return match;
}

/**
 * rb_next_match() - find the next @key in @tree
 * @key: key to match
 * @tree: tree to search
 * @cmp: operator defining l_node order
 *
 * Returns the next l_node matching @key, or NULL.
 */
static inline struct rb_node *
rb_next_match(const void *key, struct rb_node *node,
              int (*cmp)(const void *key, const struct rb_node *))
{
	node = rb_next(node);
	if (node && cmp(key, node))
		node = NULL;
	return node;
}

/**
 * rb_for_each() - iterates a subtree matching @key
 * @node: iterator
 * @key: key to match
 * @tree: tree to search
 * @cmp: operator defining l_node order
 */
#define rb_for_each(node, key, tree, cmp) \
	for ((node) = rb_find_first((key), (tree), (cmp)); \
	     (node); (node) = rb_next_match((key), (node), (cmp)))

#endif //IMITATION_OF_WORTHY_RBTREE_H
