#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <stdio.h>
#include <string.h>
#include "bt.h"

int
bt(struct bt_frame_info_s *p, int *pNumPtrs)
{
	unw_cursor_t cursor;
	unw_context_t context;
	int i;

	// get context
	unw_getcontext(&context);

	// int cursor
	unw_init_local(&cursor, &context);

	// move up the frame stack, and get its details
	i = 0;
	do
	{
		//  get IP
		unw_get_reg(&cursor, UNW_REG_IP, &p[i].ip);
		if( p[i].ip == 0 ) {
			break;
		}

		//  get symbol name, and offset
    		if( unw_get_proc_name(&cursor, p[i].symbolName, sizeof(p[i].symbolName), &p[i].offset) != 0 ) {
    			p[i].offset = 0;
    			strcat( p[i].symbolName, "error");
		}

		i++;
	} while( unw_step(&cursor) > 0 );

	*pNumPtrs = i;

	return 0;
}

static void
bt_f1()
{
	struct bt_frame_info_s fi[BT_MAX_FRAMES];
	int i, frameNum, numFrames;

	numFrames = sizeof( fi ) / sizeof( fi[0] );
	bt(&fi[0], &numFrames);

	frameNum = numFrames; // starts from reverse
	for(i=0; i<numFrames; i++, frameNum--) {
		printf("%d 0x%lx: (%s+0x%lx)\n", frameNum, fi[i].ip, fi[i].symbolName, fi[i].offset);
	}
}

int
main()
{
	bt_f1();

	return 0;
}
