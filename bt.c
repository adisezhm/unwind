#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "bt.h"

int
runCmd(const char *pCmd, char *pBuf, size_t maxBufLen)
{
	FILE *fp;

	//printf("DEBUG: runCmd( %s )\n", pCmd);

	fp = popen(pCmd, "r");
	if ( fp ) {
		while (!feof(fp))
			fgets(pBuf, maxBufLen, fp);
		pclose(fp);
	}

	//printf("DEBUG: output: %s", pBuf);

	return 0;
}

int
bt_get_func_file_line(unsigned long long offset, const char *pPgm, char *pBuf, size_t maxBufLen)
{
	char syscom[256];

	sprintf(syscom, "addr2line 0x%llx -e %s -p -C -f", offset, pPgm);

	runCmd( syscom, pBuf, maxBufLen );

	//printf("DEBUG: func-line: %s", pBuf);

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
		char tmp[512];
		char fileLineInfo[512];
		unsigned long long offset;

		offset = (unsigned long long)fi[i].ip - (unsigned long long)fi[i].pPgmStart;

		extern char *__progname;
		bt_get_func_file_line(offset, __progname, fileLineInfo, sizeof(fileLineInfo));

		snprintf(tmp, sizeof(tmp), "%d 0x%lx (ss %p so 0x%llx) (%s+0x%lx)",
			frameNum, 
			fi[i].ip, 
			fi[i].pPgmStart, 
			offset,
			fi[i].symbolName, fi[i].offset);

		printf("%-78s %s", tmp, fileLineInfo);

#if 0
		printf("%d 0x%lx (ss %p so 0x%llx) (%-32s+0x%lx) %s\n",
			frameNum, 
			fi[i].ip, 
			fi[i].pPgmStart, 
			offset,
			fi[i].symbolName, fi[i].offset,
			fileLineInfo);
#endif
	}
}


void *
bt_get_seg_start(void *pAddr)
{
	char syscom[256];
	void *pPgmStart;
	char output[512];

	sprintf(syscom, "bt.segstart.sh %d %p", getpid(), pAddr);

	runCmd( syscom, output, sizeof(output) );

	pPgmStart = (void *)strtoull(output, NULL, 16);

	return pPgmStart;
}

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

		//  get the start of the text segment, in which the IP is present
		p[i].pPgmStart = bt_get_seg_start( (void *)p[i].ip );

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

int
main()
{
	bt_f1();

	return 0;
}
