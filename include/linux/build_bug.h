#ifndef IMITATION_OF_WORTHY_BUILD_BUG_H
#define IMITATION_OF_WORTHY_BUILD_BUG_H

/**
 * static_assert - check integer constant expression at build time
 *
 * static_assert() is a wrapper for the C11 _Static_assert, with a
 * little macro magic to make the message optional (defaulting to the
 * stringification of the tested expression).
 *
 * Contrary to BUILD_BUG_ON(), static_assert() can be used at global
 * scope, but requires the expression to be an integer constant
 * expression (i.e., it is not enough that __builtin_constant_p() is
 * true for expr).
 *
 * Also note that BUILD_BUG_ON() fails the build if the condition is
 * true, while static_assert() fails the build if the expression is
 * false.
 */
#ifndef static_assert
#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)
#endif

#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)


/*
 * Compile time check that field has an expected offset
 */
#define ASSERT_STRUCT_OFFSET(type, field, expected_offset)	\
	BUILD_BUG_ON_MSG(offsetof(type, field) != (expected_offset),	\
		"Offset of " #field " in " #type " has changed.")

#endif //IMITATION_OF_WORTHY_BUILD_BUG_H
