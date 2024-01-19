#ifndef IMITATION_OF_WORTHY_RBTREE_TYPES_H
#define IMITATION_OF_WORTHY_RBTREE_TYPES_H

// 搬运 linux 的头文件

struct rb_node {
	/*
	 * 在linux内核的代码中，使用了__rb_parent_color，__rb_parent_color其实代表的是两个数据，
	 * 指针parent和颜色标记color，这是因为(aligned(sizeof(long)))让这个结构按4或者8对齐了，
	 * 加上内核中的页面分配器和slub分配器的实现原理，可以保证指针地址是2的指数，所以后两位都是0，
	 * 但是用户态编程中使用malloc编程的话应该是不能保证分配出来的地址都是2的指数的，所以这里拆成
	 * 了两个数据。这么做其实是有可能会引入并发问题的，因为分成两个字段是赋值的时候就要分开赋值，
	 * 而之前__rb_parent_color赋值只需要一个操作，不过好在看代码中并没有对__rb_parent_color
	 * 使用READ_ONCE和WRITE_ONCE
	 * */
	// unsigned long  __rb_parent_color;
	struct rb_node *parent;
	unsigned long color;

	struct rb_node *rb_right;
	struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
/* The alignment might seem pointless, but allegedly CRIS needs it */

struct rb_root {
	struct rb_node *rb_node;
};

/*
 * Leftmost-cached rbtrees.
 *
 * We do not cache the rightmost l_node based on footprint
 * size vs number of potential users that could benefit
 * from O(1) rb_last(). Just not worth it, users that want
 * this feature can always implement the logic explicitly.
 * Furthermore, users that want to cache both pointers may
 * find it a bit asymmetric, but that's ok.
 */
struct rb_root_cached {
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;
};

#define RB_ROOT (struct rb_root) { NULL, }
#define RB_ROOT_CACHED (struct rb_root_cached) { {NULL, }, NULL }

#endif //IMITATION_OF_WORTHY_RBTREE_TYPES_H
