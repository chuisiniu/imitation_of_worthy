#ifndef IMITATION_OF_WORTHY_ABM_H
#define IMITATION_OF_WORTHY_ABM_H
#include "bm.h"

struct bm *abm_create(int max_bit, struct mem_func_set *mem_f);
struct bm *abm_create_fix(int max_bit, struct mem_func_set *mem_f);

#endif //IMITATION_OF_WORTHY_ABM_H
