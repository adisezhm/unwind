#ifndef __BT_H__
#define __BT_H__

#include <libunwind.h>

struct bt_frame_info_s {
	unw_word_t ip;
	unw_word_t offset;
	char segName[256];
	char symbolName[128*3];

	void *pSegStart;
};
#define BT_MAX_FRAMES 256

extern int bt(struct bt_frame_info_s *p, int *pNumPtrs);

#endif
