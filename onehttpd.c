#define LEGALNOTICE \
" *  =====================================================================  \n"\
" *                                                                         \n"\
" *  onehttpd.c - Single file, process, thread HTTP daemon.                 \n"\
" *  Copyright (C) 2008-2010  Fong Sidney Hok Nang                          \n"\
" *                                                                         \n"\
" *  The contents of this file, except where stated otherwise, is           \n"\
" *  licensed under the GNU General Public License, version 2 (GPLv2)       \n"\
" *  as published by the Free Software Foundation. Note that this           \n"\
" *  program is not licensed under any other version of GPL                 \n"\
" *                                                                         \n"\
" *  This program is distributed in the hope that it will be useful,        \n"\
" *  but WITHOUT ANY WARRANTY; without even the implied warranty of         \n"\
" *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          \n"\
" *  GNU General Public License for more details.                           \n"\
" *                                                                         \n"\
" *=========================================================================\n"\
"\n"
#/*  (GPLv2 is included near the bottom of the source file) */

#if defined(__unix__) || defined(__unix) || \
	(defined(__APPLE__) && defined(__MACH__))
#define UNIX_ENOUGH
#endif

#define USAGE_BASE \
"Usage: onehttpd [OPTIONS]... DOCROOT                                       \n"\
"Start a webserver with document root at DOCROOT                             \n"\
"                                                                           \n"\
"  -G       Displays legal notices on copyrights, disclaimers, etc.         \n"\
"  -l       Disable directory listings (enabled by default)                 \n"\
"  -p PORT  Listen to port (default port 8080)                              \n"\
"  -q       Quiet, only show critical/fatal errors                          \n"\
"  -Q       Very quiet, only show fatal errors                              \n"\
"  -v       Verbose, show informative messages                              \n"\
"  -V       Very verbose, show also debug messages                          \n"\
"  -d       Run a dummy server that serves a static page instead of DOCROOT \n"\
"  -u       Use 'charset=utf-8' in Content-Type for text files and listings.\n"\
"                                                                           \n"\

#ifdef UNIX_ENOUGH
#define USAGE USAGE_BASE \
"Example: onehttpd -p 8008 /var/www   # Serve files in /var/www on port 8008\n\n"
#else
#define USAGE USAGE_BASE \
"Example: onehttpd.exe C:\\WWW         # Serve files in C:\\WWW on port 8080  \n\n"\
"HINT: In Windows, you can just drag and drop a directory onto onehttpd.exe \n\n"
#endif

#/* (Mis-)Features:
# *
# * - Designed to run on both WinNT and UNIX platforms (although currently only
# *   tested on Linux, WinXP)
# * - Clients tested: Chrome, Firefox, IE5, IE6. (shouldn't matter actually)
# * - Small and simple design
# * - Insecure. I've taken extra care with buffers but I'm no experienced C
#     coder, and my system programming (esp with Win32) is lacking. OS related
#     logic holes are be abound.
# * - Non-standards conformant, although intended to support a subset of HTTP/1.0
#*/

#/* Known Issues:
# *
# * - Due to the simple design, and my amatuer systems programming skills, this
#     httpd is not intended to be robust. It won't likely be able to serve more
#     than a few concurrent requests without showing problems.
# * - There is a hard coded MAX_FILE_DESCRIPTORS constant in the code, meaning
#     that there's a static limit to the number of concurrent connections. This
#     is not a big design flaw, since most systems have a file descriptor limit
#     anyway but it does make the code a bit ugly. I'm not going to fix this as
#     yet since onehttpd is not supposed to be used in high volume sites anyway.
# */

#/* About the source:
# *
# * - Please set your tabs to occupy 4 characters. Otherwise some indentation
# *   might look other than intended. ( For Vim users: tabstop=4 shiftwidth=4
# *   noexpandtab )
# * - Most braces are supposed to be on their own line, but it's a new acquired
# *   habit of mine and I haven't waned the old practice. And sometimes there's
# *   an intentional deviation.
# * - A Makefile (mostly for myself) is embeded in the C file (so actually this
# *   file is a polyglot of some sort).
# * - A (windows) resource file is embeded at the end, which contains an icon
# *   resource and some VERSIONINFO stuff. The icon is actually embeded in the
# *   "Makefile" section, in hex form and decoded by perl/gunzip. (Yay, another
# *   polyglot....)
# * - Due to the polyglot nature of this file, you might want to create symlinks
# *   like "ln -s onehttpd.c Makefile" to make things a bit more convenient.
#*/

#/* Disclaimer: the author has minimal experience with the Win32 API, things
# * might have been done the wrong way. Suggestions welcome. */

#/* For Makefile:
ONEHTTPD_VERSION_MAJOR=0
ONEHTTPD_VERSION_MINOR=8
#*/

#/* For C */
#define ONEHTTPD_VERSION_MAJOR 0
#define ONEHTTPD_VERSION_MINOR 8
#define ONEHTTPD_VERSION_STRING "0.8"
#define ONEHTTPD_VERSION_STRING_FULL "onehttpd/" ONEHTTPD_VERSION_STRING

# /* This is the Makefile part
ifeq ($(OS),Windows_NT)
	CC=i586-mingw32msvc-gcc
	TARGET=onehttpd.exe
else
	CC=gcc
	TARGET=onehttpd
endif

all: $(TARGET)

# just need to consider distributing the win32 exe.
dist: onehttpd.exe
	mkdir -p dist/ && cp onehttpd.exe dist/onehttpd-${ONEHTTPD_VERSION_MAJOR}.${ONEHTTPD_VERSION_MINOR}.exe && i586-mingw32msvc-strip dist/onehttpd-${ONEHTTPD_VERSION_MAJOR}.${ONEHTTPD_VERSION_MINOR}.exe; chmod 644 dist/onehttpd-${ONEHTTPD_VERSION_MAJOR}.${ONEHTTPD_VERSION_MINOR}.exe; cp onehttpd.c dist/onehttpd-${ONEHTTPD_VERSION_MAJOR}.${ONEHTTPD_VERSION_MINOR}.c; echo 'REMEMBER TO BUMP VERSION';

onehttpd: onehttpd.c
	gcc -Wall -g -fno-strict-aliasing onehttpd.c -o onehttpd

onehttpd.exe: onehttpd.c onehttpd.res
	i586-mingw32msvc-gcc -Os -Wall -fno-strict-aliasing onehttpd.c onehttpd.res -lwsock32 -o onehttpd.exe

onehttpd.res: onehttpd.c onehttpd.ico
	i586-mingw32msvc-windres -D IS_RESOURCE_FILE -i onehttpd.c --input-format=rc -o onehttpd.res -O coff 

# The long string of hex is the hexdump of the gzipped icon used in the EXE.

# LEGAL NOTICE: The icon is not released under the GPL. It is a mere
# aggregation and not a derived work of the main program. (the main reason for
# this is because I do not want to include the "source" for the icon, which is
# a GIMP xcf file, for convenience reasons)
#
# The following line of hex string, excluding the perl/shell code, is hereby
# released into the public domain.
onehttpd.ico:
	perl -e 'print pack("H*", "1f8b080866ea9c4700036f6e6568747470642e69636f00636060044205050620c9c1b0828381418c818141038881420c0e0c10715c40734a1f831610eb4e9bc0a03f7d2283eeeca90c96b3a73198ad5c04c48b19ecb6af67b0dfb191c1fdc85e068f63fb18bc4f1f66b87aef2ec38d07f719ee3d7ac4701f889f3e7d8ad3fc51300a46c1e0053c840021ed0c82400a86110c064120c02b0fc6c4c8434c429207f3b1ea67e2678471b0c933b1f231e39007dbc2cfcb2b2008331fe67e24c0c8c4c488e17f42e14335796c71428afc289fb67c2e0e36167cf2d8f213329f859d939b907de880b03c45d99bf60000c68270f5be080000");' | gunzip -c > onehttpd.ico

clean:
	rm -f onehttpd.exe onehttpd tags onehttpd.res onehttpd.ico

define begin_c_program
# End Makefile part */

/* TODO list: */
/*
 * - Full HTTP/1.0 support
 * - Full HTTP/1.1 support (wishlist...)
 * - other FIXME/TODO's scattered around.
 * - plugin support for dynamic stuff
 * - handle signals? (what about win32?)
 * - add an easy "installer" for win32, so that people can drag/drop a
 *   directory onto the link to start the server (it actually works now, but
 *   user can't specify any options this way). either create a LNK file with
 *   common options, or do some WIN32 api stuff to popup and ask?
 * - more stress tests on more platforms. maybe make some unit tests and
 *   integration tests etc..
 * - TODO: query strings etc.
 */

#ifndef IS_RESOURCE_FILE

/* hardcoded values that might be useful to be changed */

#define MAX_FILE_DESCRIPTORS 64

/* ******** INCLUDES ******* (*/
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef WIN32

/* Need at least 0x0500 to use GetFileSizeEx on MinGW */
#define WINVER 0x0500

#include <windows.h>
typedef int socklen_t;
typedef DWORD err_t;
#define close(fd) closesocket(fd)

struct __file_t {
	HANDLE h;
	int open_options;
	OVERLAPPED async;
	char async_working; /* whether in the middle of an async operation */
	DWORD async_offset;
};

typedef struct __file_t* file_t;

struct __dir_t {
	HANDLE h;
	WIN32_FIND_DATAW ffd;
	char nomorefiles;
};

typedef struct __dir_t dir_t;
#define GETERROR() (GetLastError())
#define WTFERR "unexpected error %ld"

#else /* ! WIN32 */

#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <dirent.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
typedef int file_t;
typedef int err_t;
typedef DIR dir_t;
#define GETERROR() (errno)
#define WTFERR "unexpected error %d"

#define SOCKET_ERROR (-1)

#endif


/* )********** DEFS ******** (*/

#define LEVEL_ERROR	0 /* causes the program to halt almost immediately */
#define LEVEL_CRIT	1 /* grave error, probably some inadequately handled errors */
#define LEVEL_WARN	2 /* warning signs, might be serious */
#define LEVEL_INFO	3 /* useful information */
#define LEVEL_DEBUG	4 /* for debugging */

#define EXIT_SUCCESS 0
#define EXIT_SYS  1 /* fatal error due to failing syscall, which is not unexpected */
#define EXIT_USER 2 /* error due to user input ( and is not due to immediate failing syscall ) */
#define EXIT_BUG  3 /* unlikely error, potentially due to a bug */
#define EXIT_MEM  4 /* exit code when stuff like malloc/realloc/calloc fails, used because when they fail error handling is probably meaningless */

#define False 0
#define True (!False)

#define VERBOSE_ENOUGH_FOR(lvl) (slib_verbosity >= (lvl))
int slib_verbosity = 2;
const char *slib_verbose_labels[] = {"ERROR", "CRIT", "WARN", "INFO", "DEBUG"};
typedef unsigned long word_t;


/* assumes fmt is a compile time constant string */
#define slib_println(lvl,fmt,...) ( ((lvl) <= slib_verbosity) ? fprintf(stderr, "(%s:%d):%s\t- " fmt "\n", __FILE__, __LINE__, slib_verbose_labels[(lvl)], ##__VA_ARGS__) : 0 )

#define DEBUG(fmt,...) (slib_println(LEVEL_DEBUG, fmt, ##__VA_ARGS__))
#define CRIT(fmt,...) (slib_println(LEVEL_CRIT, fmt, ##__VA_ARGS__))
#define INFO(fmt,...) (slib_println(LEVEL_INFO, fmt, ##__VA_ARGS__))
#define WARN(fmt,...) (slib_println(LEVEL_WARN, fmt, ##__VA_ARGS__))
#define DIE( exit_code, fmt, ... ) { slib_println( LEVEL_ERROR, fmt, ##__VA_ARGS__ ); exit( exit_code ); }
#define ABORT( fmt, ... ) {          slib_println( LEVEL_ERROR, fmt, ##__VA_ARGS__ ); abort() ; }
#define ASSERTM(q,fmt,...) { if ((!(q))) { ABORT("assertion failed:" fmt, ##__VA_ARGS__); } }
#define ASSERT(q) { if ((!(q))) { ABORT("assertion failed"); } }

#define MIN(a,b) ( ((a)<(b))?(a):(b) )

#define ROGUE "rogue"

#define ISHEX(c) ((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))

/* FIXME: this macro probably has network byte order problems (but then I don't have a big endian machine to test it with...) */
#define IPADDRESS(ip) (unsigned int) (((ip)>>0)&0xff), (unsigned int) (((ip)>>8)&0xff), (unsigned int) (((ip)>>16)&0xff), (unsigned int) (((ip)>>24)&0xff)

#define BUF_CHUNK (1024*128)
#define LINKED_BLOCK_CHUNK (1024*128)
#define MAX_READ_ROUNDS (32)

/* 40 KB is the hard coded maximum size of a request */
#define MAX_REQUEST_SIZE (1024*40)

/* maximum amount of file data we will read into memory per request */
/* this is not really a "hard" limit, the actual hard limit should be this value plus one BUF_CHUNK */
#define MAX_OUTPUT_QUEUE_SIZE (4096*1024)

#define HTTP_SERVER_HEADER \
	"Server: " ONEHTTPD_VERSION_STRING_FULL "\r\n"

#define HTTP(x) (x)

/* let's hope I don't burn in a special hell for doing this ... */
#define HTTP__CODE(num,desc) (const char *) (num), (desc)


/* )****** STRUCTURES ****** (*/

/* Response codes copied from rfc1945 */
const char *http_code_desc[] =
{
	HTTP__CODE(200, "OK"),
	HTTP__CODE(201, "Created"),
	HTTP__CODE(202, "Accepted"),
	HTTP__CODE(204, "No Content"),

	HTTP__CODE(300, "Multiple Choices"),
	HTTP__CODE(301, "Moved Permanently"),
	HTTP__CODE(302, "Found"),
	HTTP__CODE(304, "Not Modified"),

	HTTP__CODE(400, "Bad Request"),
	HTTP__CODE(401, "Unauthorized"),
	HTTP__CODE(403, "Forbidden"),
	HTTP__CODE(404, "Not Found"),

	HTTP__CODE(500, "Internal Server Error"),
	HTTP__CODE(501, "Not Implemented"),
	HTTP__CODE(502, "Bad Gateway"),
	HTTP__CODE(503, "Service Unavailable"),

	NULL, NULL
};

/* Note: not all results are used, or even meaningful by functions that return
 * these values */
enum result_t
{
	SUCCESS,      /* success */
	FAIL,         /* error occurred. we probably want to close the connection */
	NEED_MORE,    /* need more input. wait for client to send more */
	ALREADY_DONE, /* information already processed before */

	OVERUNDERFLOW, /* for intval() */

	FAIL_ACCESS,
	FAIL_NOTFOUND,
	FAIL_SYS,
	CALL_AGAIN,
	WOULD_BLOCK,
	UNKNOWN_RESULT
};

enum http_method
{
	UNKNOWN,
	GET,
	HEAD,
	POST,
	/* TODO more here */
};

struct LinkedBlockItem
{
	struct LinkedBlockItem *next;
	struct LinkedBlockItem *tail_block; /* maintained only by the head block */
	size_t length; /* maintained only by head block */
	int data_start;
	int data_end;
	unsigned char data[LINKED_BLOCK_CHUNK];
};

typedef struct LinkedBlockItem* LinkedBlocks;

/* TODO: more should be implemented here */
struct file_properties {
	unsigned long long size;
};


struct Request
{
	/* network stuff */
	int fd;
	struct sockaddr_in remote_addr;

	/* buffer stuff */
	char *i_buffer;
	int i_buffer_len;
	int i_buffer_siz;
	char *last_read;

	char *h_buffer;
	int h_buffer_len;
	int h_buffer_siz;
	int h_sent;

	unsigned char *f_buffer;

	LinkedBlocks o_queue;

	char **lines; /* array of pointers to beginning of lines in i_buffer */
	int lines_siz;
	int num_lines;
	int processed_lines;

	/* file handle for dumping static files */
	file_t fhandle;

	/* general status stuff */
	char had_enough_input; /* finished reading / not expecting any more input */
	char h_done; /* finished generating headers */
	char o_done; /* finished generating contents */
	char done_tokenizing_headers; /* done tokenizing headers */

	/* HTTP related stuff. These generally do not require additional mallocs as
	 * the strings are pointers to i_buffer */
	/* Reference: http://tools.ietf.org/html/rfc1945 */
	enum http_method method;

	const char *request_uri;  /* don't free(), points to i_buffer offset */
	const char *user_agent;   /* don't free(), points to i_buffer offset */
	const char *referer;      /* don't free(), points to i_buffer offset */

	const void *req_content; /*  don't free(), points to i_buffer offset (or past it) */

	const char *content_type; /* don't free(), points to mime_dataraw offset */

	char is_simple; /* "Simple-Request" as opposed to "Full-Request" */

	int ver_major;
	int ver_minor;

	int resp_status;
};

/* a common static global buffer for size/speed purposes */
static char buf256[256];

/* there are about 669 values in the raw data, so open an approx sized array */
/* these are pointers to the raw data */
const char *mime_ext[700];
const char *mime_value[700];
int mime_num = 0;
const char *mime_HTML = NULL;

/* mime data grabbed from /etc/mime.types (Debian) with an associated extension, double null terminated */
/*  cat /etc/mime.types |  perl -ne 'next if not /\t+/; chomp; ($a, $b) = split(/\t+/); @exts = split(/\s/, $b); foreach (@exts) { print "$_\\000$a\\000"; } ' */
const char mime_dataraw[] = 
"ez\000application/andrew-inset\000anx\000application/annodex\000atom\000application/atom+xml\000atomcat\000application/atomcat+xml\000atomsrv\000application/atomserv+xml\000lin\000application/bbolin\000cap\000application/cap\000pcap\000application/cap\000cu\000application/cu-seeme\000davmount\000application/davmount+xml\000tsp\000application/dsptype\000es\000application/ecmascript\000spl\000application/futuresplash\000hta\000application/hta\000jar\000application/java-archive\000ser\000application/java-serialized-object\000class\000application/java-vm\000js\000application/javascript\000m3g\000application/m3g\000hqx\000application/mac-binhex40\000cpt\000application/mac-compactpro\000nb\000application/mathematica\000nbp\000application/mathematica\000mdb\000application/msaccess\000doc\000application/msword\000dot\000application/msword\000mxf\000application/mxf\000bin\000application/octet-stream\000oda\000application/oda\000ogx\000application/ogg\000pdf\000application/pdf\000key\000application/pgp-keys\000pgp\000application/pgp-signature\000prf\000application/pics-rules\000ps\000application/postscript\000ai\000application/postscript\000eps\000application/postscript\000epsi\000application/postscript\000epsf\000application/postscript\000eps2\000application/postscript\000eps3\000application/postscript\000rar\000application/rar\000rdf\000application/rdf+xml\000rss\000application/rss+xml\000rtf\000application/rtf\000smi\000application/smil\000smil\000application/smil\000xhtml\000application/xhtml+xml\000xht\000application/xhtml+xml\000xml\000application/xml\000xsl\000application/xml\000xsd\000application/xml\000xspf\000application/xspf+xml\000zip\000application/zip\000apk\000application/vnd.android.package-archive\000cdy\000application/vnd.cinderella\000kml\000application/vnd.google-earth.kml+xml\000kmz\000application/vnd.google-earth.kmz\000xul\000application/vnd.mozilla.xul+xml\000xls\000application/vnd.ms-excel\000xlb\000application/vnd.ms-excel\000xlt\000application/vnd.ms-excel\000cat\000application/vnd.ms-pki.seccat\000stl\000application/vnd.ms-pki.stl\000ppt\000application/vnd.ms-powerpoint\000pps\000application/vnd.ms-powerpoint\000odc\000application/vnd.oasis.opendocument.chart\000odb\000application/vnd.oasis.opendocument.database\000odf\000application/vnd.oasis.opendocument.formula\000odg\000application/vnd.oasis.opendocument.graphics\000otg\000application/vnd.oasis.opendocument.graphics-template\000odi\000application/vnd.oasis.opendocument.image\000odp\000application/vnd.oasis.opendocument.presentation\000otp\000application/vnd.oasis.opendocument.presentation-template\000ods\000application/vnd.oasis.opendocument.spreadsheet\000ots\000application/vnd.oasis.opendocument.spreadsheet-template\000odt\000application/vnd.oasis.opendocument.text\000odm\000application/vnd.oasis.opendocument.text-master\000ott\000application/vnd.oasis.opendocument.text-template\000oth\000application/vnd.oasis.opendocument.text-web\000xlsx\000application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\000xltx\000application/vnd.openxmlformats-officedocument.spreadsheetml.template\000pptx\000application/vnd.openxmlformats-officedocument.presentationml.presentation\000ppsx\000application/vnd.openxmlformats-officedocument.presentationml.slideshow\000potx\000application/vnd.openxmlformats-officedocument.presentationml.template\000docx\000application/vnd.openxmlformats-officedocument.wordprocessingml.document\000dotx\000application/vnd.openxmlformats-officedocument.wordprocessingml.template\000cod\000application/vnd.rim.cod\000mmf\000application/vnd.smaf\000sdc\000application/vnd.stardivision.calc\000sds\000application/vnd.stardivision.chart\000sda\000application/vnd.stardivision.draw\000sdd\000application/vnd.stardivision.impress\000sdf\000application/vnd.stardivision.math\000sdw\000application/vnd.stardivision.writer\000sgl\000application/vnd.stardivision.writer-global\000sxc\000application/vnd.sun.xml.calc\000stc\000application/vnd.sun.xml.calc.template\000sxd\000application/vnd.sun.xml.draw\000std\000application/vnd.sun.xml.draw.template\000sxi\000application/vnd.sun.xml.impress\000sti\000application/vnd.sun.xml.impress.template\000sxm\000application/vnd.sun.xml.math\000sxw\000application/vnd.sun.xml.writer\000sxg\000application/vnd.sun.xml.writer.global\000stw\000application/vnd.sun.xml.writer.template\000sis\000application/vnd.symbian.install\000vsd\000application/vnd.visio\000wbxml\000application/vnd.wap.wbxml\000wmlc\000application/vnd.wap.wmlc\000wmlsc\000application/vnd.wap.wmlscriptc\000wpd\000application/vnd.wordperfect\000wp5\000application/vnd.wordperfect5.1\000wk\000application/x-123\0007z\000application/x-7z-compressed\000abw\000application/x-abiword\000dmg\000application/x-apple-diskimage\000bcpio\000application/x-bcpio\000torrent\000application/x-bittorrent\000cab\000application/x-cab\000cbr\000application/x-cbr\000cbz\000application/x-cbz\000cdf\000application/x-cdf\000cda\000application/x-cdf\000vcd\000application/x-cdlink\000pgn\000application/x-chess-pgn\000cpio\000application/x-cpio\000csh\000application/x-csh\000deb\000application/x-debian-package\000udeb\000application/x-debian-package\000dcr\000application/x-director\000dir\000application/x-director\000dxr\000application/x-director\000dms\000application/x-dms\000wad\000application/x-doom\000dvi\000application/x-dvi\000rhtml\000application/x-httpd-eruby\000pfa\000application/x-font\000pfb\000application/x-font\000gsf\000application/x-font\000pcf\000application/x-font\000pcf.Z\000application/x-font\000mm\000application/x-freemind\000spl\000application/x-futuresplash\000gnumeric\000application/x-gnumeric\000sgf\000application/x-go-sgf\000gcf\000application/x-graphing-calculator\000gtar\000application/x-gtar\000tgz\000application/x-gtar\000taz\000application/x-gtar\000hdf\000application/x-hdf\000phtml\000application/x-httpd-php\000pht\000application/x-httpd-php\000php\000application/x-httpd-php\000phps\000application/x-httpd-php-source\000php3\000application/x-httpd-php3\000php3p\000application/x-httpd-php3-preprocessed\000php4\000application/x-httpd-php4\000php5\000application/x-httpd-php5\000ica\000application/x-ica\000info\000application/x-info\000ins\000application/x-internet-signup\000isp\000application/x-internet-signup\000iii\000application/x-iphone\000iso\000application/x-iso9660-image\000jam\000application/x-jam\000jnlp\000application/x-java-jnlp-file\000jmz\000application/x-jmol\000chrt\000application/x-kchart\000kil\000application/x-killustrator\000skp\000application/x-koan\000skd\000application/x-koan\000skt\000application/x-koan\000skm\000application/x-koan\000kpr\000application/x-kpresenter\000kpt\000application/x-kpresenter\000ksp\000application/x-kspread\000kwd\000application/x-kword\000kwt\000application/x-kword\000latex\000application/x-latex\000lha\000application/x-lha\000lyx\000application/x-lyx\000lzh\000application/x-lzh\000lzx\000application/x-lzx\000frm\000application/x-maker\000maker\000application/x-maker\000frame\000application/x-maker\000fm\000application/x-maker\000fb\000application/x-maker\000book\000application/x-maker\000fbdoc\000application/x-maker\000mif\000application/x-mif\000wmd\000application/x-ms-wmd\000wmz\000application/x-ms-wmz\000com\000application/x-msdos-program\000exe\000application/x-msdos-program\000bat\000application/x-msdos-program\000dll\000application/x-msdos-program\000msi\000application/x-msi\000nc\000application/x-netcdf\000pac\000application/x-ns-proxy-autoconfig\000dat\000application/x-ns-proxy-autoconfig\000nwc\000application/x-nwc\000o\000application/x-object\000oza\000application/x-oz-application\000p7r\000application/x-pkcs7-certreqresp\000crl\000application/x-pkcs7-crl\000pyc\000application/x-python-code\000pyo\000application/x-python-code\000qgs\000application/x-qgis\000shp\000application/x-qgis\000shx\000application/x-qgis\000qtl\000application/x-quicktimeplayer\000rpm\000application/x-redhat-package-manager\000rb\000application/x-ruby\000sh\000application/x-sh\000shar\000application/x-shar\000swf\000application/x-shockwave-flash\000swfl\000application/x-shockwave-flash\000scr\000application/x-silverlight\000sit\000application/x-stuffit\000sitx\000application/x-stuffit\000sv4cpio\000application/x-sv4cpio\000sv4crc\000application/x-sv4crc\000tar\000application/x-tar\000tcl\000application/x-tcl\000gf\000application/x-tex-gf\000pk\000application/x-tex-pk\000texinfo\000application/x-texinfo\000texi\000application/x-texinfo\000~\000application/x-trash\000%\000application/x-trash\000bak\000application/x-trash\000old\000application/x-trash\000sik\000application/x-trash\000t\000application/x-troff\000tr\000application/x-troff\000roff\000application/x-troff\000man\000application/x-troff-man\000me\000application/x-troff-me\000ms\000application/x-troff-ms\000ustar\000application/x-ustar\000src\000application/x-wais-source\000wz\000application/x-wingz\000crt\000application/x-x509-ca-cert\000xcf\000application/x-xcf\000fig\000application/x-xfig\000xpi\000application/x-xpinstall\000amr\000audio/amr\000awb\000audio/amr-wb\000amr\000audio/amr\000awb\000audio/amr-wb\000axa\000audio/annodex\000au\000audio/basic\000snd\000audio/basic\000flac\000audio/flac\000mid\000audio/midi\000midi\000audio/midi\000kar\000audio/midi\000mpga\000audio/mpeg\000mpega\000audio/mpeg\000mp2\000audio/mpeg\000mp3\000audio/mpeg\000m4a\000audio/mpeg\000m3u\000audio/mpegurl\000oga\000audio/ogg\000ogg\000audio/ogg\000spx\000audio/ogg\000sid\000audio/prs.sid\000aif\000audio/x-aiff\000aiff\000audio/x-aiff\000aifc\000audio/x-aiff\000gsm\000audio/x-gsm\000m3u\000audio/x-mpegurl\000wma\000audio/x-ms-wma\000wax\000audio/x-ms-wax\000ra\000audio/x-pn-realaudio\000rm\000audio/x-pn-realaudio\000ram\000audio/x-pn-realaudio\000ra\000audio/x-realaudio\000pls\000audio/x-scpls\000sd2\000audio/x-sd2\000wav\000audio/x-wav\000alc\000chemical/x-alchemy\000cac\000chemical/x-cache\000cache\000chemical/x-cache\000csf\000chemical/x-cache-csf\000cbin\000chemical/x-cactvs-binary\000cascii\000chemical/x-cactvs-binary\000ctab\000chemical/x-cactvs-binary\000cdx\000chemical/x-cdx\000cer\000chemical/x-cerius\000c3d\000chemical/x-chem3d\000chm\000chemical/x-chemdraw\000cif\000chemical/x-cif\000cmdf\000chemical/x-cmdf\000cml\000chemical/x-cml\000cpa\000chemical/x-compass\000bsd\000chemical/x-crossfire\000csml\000chemical/x-csml\000csm\000chemical/x-csml\000ctx\000chemical/x-ctx\000cxf\000chemical/x-cxf\000cef\000chemical/x-cxf\000smi\000#chemical/x-daylight-smiles\000emb\000chemical/x-embl-dl-nucleotide\000embl\000chemical/x-embl-dl-nucleotide\000spc\000chemical/x-galactic-spc\000inp\000chemical/x-gamess-input\000gam\000chemical/x-gamess-input\000gamin\000chemical/x-gamess-input\000fch\000chemical/x-gaussian-checkpoint\000fchk\000chemical/x-gaussian-checkpoint\000cub\000chemical/x-gaussian-cube\000gau\000chemical/x-gaussian-input\000gjc\000chemical/x-gaussian-input\000gjf\000chemical/x-gaussian-input\000gal\000chemical/x-gaussian-log\000gcg\000chemical/x-gcg8-sequence\000gen\000chemical/x-genbank\000hin\000chemical/x-hin\000istr\000chemical/x-isostar\000ist\000chemical/x-isostar\000jdx\000chemical/x-jcamp-dx\000dx\000chemical/x-jcamp-dx\000kin\000chemical/x-kinemage\000mcm\000chemical/x-macmolecule\000mmd\000chemical/x-macromodel-input\000mmod\000chemical/x-macromodel-input\000mol\000chemical/x-mdl-molfile\000rd\000chemical/x-mdl-rdfile\000rxn\000chemical/x-mdl-rxnfile\000sd\000chemical/x-mdl-sdfile\000sdf\000chemical/x-mdl-sdfile\000tgf\000chemical/x-mdl-tgf\000mif\000#chemical/x-mif\000mcif\000chemical/x-mmcif\000mol2\000chemical/x-mol2\000b\000chemical/x-molconn-Z\000gpt\000chemical/x-mopac-graph\000mop\000chemical/x-mopac-input\000mopcrt\000chemical/x-mopac-input\000mpc\000chemical/x-mopac-input\000zmt\000chemical/x-mopac-input\000moo\000chemical/x-mopac-out\000mvb\000chemical/x-mopac-vib\000asn\000chemical/x-ncbi-asn1\000prt\000chemical/x-ncbi-asn1-ascii\000ent\000chemical/x-ncbi-asn1-ascii\000val\000chemical/x-ncbi-asn1-binary\000aso\000chemical/x-ncbi-asn1-binary\000asn\000chemical/x-ncbi-asn1-spec\000pdb\000chemical/x-pdb\000ent\000chemical/x-pdb\000ros\000chemical/x-rosdal\000sw\000chemical/x-swissprot\000vms\000chemical/x-vamas-iso14976\000vmd\000chemical/x-vmd\000xtel\000chemical/x-xtel\000xyz\000chemical/x-xyz\000gif\000image/gif\000ief\000image/ief\000jpeg\000image/jpeg\000jpg\000image/jpeg\000jpe\000image/jpeg\000pcx\000image/pcx\000png\000image/png\000svg\000image/svg+xml\000svgz\000image/svg+xml\000tiff\000image/tiff\000tif\000image/tiff\000djvu\000image/vnd.djvu\000djv\000image/vnd.djvu\000wbmp\000image/vnd.wap.wbmp\000cr2\000image/x-canon-cr2\000crw\000image/x-canon-crw\000ras\000image/x-cmu-raster\000cdr\000image/x-coreldraw\000pat\000image/x-coreldrawpattern\000cdt\000image/x-coreldrawtemplate\000cpt\000image/x-corelphotopaint\000erf\000image/x-epson-erf\000ico\000image/x-icon\000art\000image/x-jg\000jng\000image/x-jng\000bmp\000image/x-ms-bmp\000nef\000image/x-nikon-nef\000orf\000image/x-olympus-orf\000psd\000image/x-photoshop\000pnm\000image/x-portable-anymap\000pbm\000image/x-portable-bitmap\000pgm\000image/x-portable-graymap\000ppm\000image/x-portable-pixmap\000rgb\000image/x-rgb\000xbm\000image/x-xbitmap\000xpm\000image/x-xpixmap\000xwd\000image/x-xwindowdump\000eml\000message/rfc822\000igs\000model/iges\000iges\000model/iges\000msh\000model/mesh\000mesh\000model/mesh\000silo\000model/mesh\000wrl\000model/vrml\000vrml\000model/vrml\000x3dv\000model/x3d+vrml\000x3d\000model/x3d+xml\000x3db\000model/x3d+binary\000manifest\000text/cache-manifest\000ics\000text/calendar\000icz\000text/calendar\000css\000text/css\000csv\000text/csv\000323\000text/h323\000html\000text/html\000htm\000text/html\000shtml\000text/html\000uls\000text/iuls\000mml\000text/mathml\000asc\000text/plain\000txt\000text/plain\000text\000text/plain\000pot\000text/plain\000brf\000text/plain\000rtx\000text/richtext\000sct\000text/scriptlet\000wsc\000text/scriptlet\000tm\000text/texmacs\000ts\000text/texmacs\000tsv\000text/tab-separated-values\000jad\000text/vnd.sun.j2me.app-descriptor\000wml\000text/vnd.wap.wml\000wmls\000text/vnd.wap.wmlscript\000bib\000text/x-bibtex\000boo\000text/x-boo\000h++\000text/x-c++hdr\000hpp\000text/x-c++hdr\000hxx\000text/x-c++hdr\000hh\000text/x-c++hdr\000c++\000text/x-c++src\000cpp\000text/x-c++src\000cxx\000text/x-c++src\000cc\000text/x-c++src\000h\000text/x-chdr\000htc\000text/x-component\000csh\000text/x-csh\000c\000text/x-csrc\000d\000text/x-dsrc\000diff\000text/x-diff\000patch\000text/x-diff\000hs\000text/x-haskell\000java\000text/x-java\000lhs\000text/x-literate-haskell\000moc\000text/x-moc\000p\000text/x-pascal\000pas\000text/x-pascal\000gcd\000text/x-pcs-gcd\000pl\000text/x-perl\000pm\000text/x-perl\000py\000text/x-python\000scala\000text/x-scala\000etx\000text/x-setext\000sh\000text/x-sh\000tcl\000text/x-tcl\000tk\000text/x-tcl\000tex\000text/x-tex\000ltx\000text/x-tex\000sty\000text/x-tex\000cls\000text/x-tex\000vcs\000text/x-vcalendar\000vcf\000text/x-vcard\0003gp\000video/3gpp\000axv\000video/annodex\000dl\000video/dl\000dif\000video/dv\000dv\000video/dv\000fli\000video/fli\000gl\000video/gl\000mpeg\000video/mpeg\000mpg\000video/mpeg\000mpe\000video/mpeg\000mp4\000video/mp4\000qt\000video/quicktime\000mov\000video/quicktime\000ogv\000video/ogg\000mxu\000video/vnd.mpegurl\000flv\000video/x-flv\000lsf\000video/x-la-asf\000lsx\000video/x-la-asf\000mng\000video/x-mng\000asf\000video/x-ms-asf\000asx\000video/x-ms-asf\000wm\000video/x-ms-wm\000wmv\000video/x-ms-wmv\000wmx\000video/x-ms-wmx\000wvx\000video/x-ms-wvx\000avi\000video/x-msvideo\000movie\000video/x-sgi-movie\000mpv\000video/x-matroska\000mkv\000video/x-matroska\000ice\000x-conference/x-cooltalk\000sisx\000x-epoc/x-sisx-app\000vrm\000x-world/x-vrml\000vrml\000x-world/x-vrml\000wrl\000x-world/x-vrml\000";

/* index of requests[] is the file descriptor */
struct Request *requests[MAX_FILE_DESCRIPTORS];

char config_dummy = False;
char config_utf8text = False;
char config_list_directories = True;
int config_bind_port = 8080;
char *config_bind_addr = NULL; /* TODO */
char *config_doc_root = NULL;

/* )********* UTILS ******** (*/

#ifdef WIN32
char is_affected_by_xp_mb_bug() {
	int ans;
	unsigned char buf[100];
	static char result = 77; // not True not False...
	if (result != 77) {
		return result;
	}

	memset(buf, 0, sizeof(buf));
	/* According to the docs, this should attempt to convert ".\xc2." from UTF8
	 * to UCS-2, and give an error (i.e. return 0) since invalid characters are
	 * encountered. However... */
	ans = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, ".\xc2.", -1, (WCHAR*) buf, 100);
	if (ans && memcmp(buf, ".\0.\0\0\0", 6) == 0) {
		/* ... I do suspect that in the msdn documentation ""Windows XP: To
		 * prevent the security problem of the non-shortest-form versions of
		 * UTF-8 characters, MultiByteToWideChar deletes these characters.""
		 * does document this "feature" in an obscure manner... */
		/* For examples of pwnage, see eg. http://www.coresecurity.com/content/advisory-vmware */
		WARN("Warning: Disabling non-ASCII file access due to bug in MultiByteToWideChar!");
		result = True;
	} else {
		result = False;
	}
	return result;
}

char is_seven_bit_clean(const char *s) {
	for (; *s != '\0'; s++) {
		if (*s & 0x80) {
			return False;
		}
	}
	return True;
}

// A wrapper around MultiByteToWideChar that refuses to convert any non-ASCII input to UCS-2 on buggy systems.
int MultiByteToWideCharWrapper(
		unsigned int CodePage,
		DWORD dwFlags,
		LPCSTR lpMultiByteStr,
		int cbMultiByte,
		LPWSTR lpWideCharStr,
		int cchWideChar
		) {
	if (is_affected_by_xp_mb_bug() && !is_seven_bit_clean(lpMultiByteStr)) {
		WARN("Refusing to try UTF-8 conversion with a buggy MultiByteToWideChar()! [%s]", lpMultiByteStr);
		return 0;
	} else {
		return MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
	}
}


#else  /* ! WIN32 */
// No implementation.
#endif

LinkedBlocks lb_new()
{
	struct LinkedBlockItem *ret;
	ret = malloc(sizeof(struct LinkedBlockItem));
	ret->tail_block = ret;
	ret->data_start = 0;
	ret->data_end = 0;
	ret->length = 0;
	ret->next = NULL;
	return ret;
}

void lb_enqueue( LinkedBlocks b, const void *ptr, size_t count )
{
	struct LinkedBlockItem *tail;
	int chunklen;

	b->length += count;

	tail = b->tail_block;

	while (count)
	{
		if ( tail->data_end == LINKED_BLOCK_CHUNK )
		{
			tail = malloc(sizeof(struct LinkedBlockItem));
			tail->data_start = tail->data_end = 0;
			tail->next = NULL;
			b->tail_block->next = tail;
			b->tail_block = tail;
		}

		chunklen = MIN( count, ( LINKED_BLOCK_CHUNK - tail->data_end ) );
		memcpy( tail->data + tail->data_end, ptr, chunklen );

		tail->data_end += chunklen;
		ptr += chunklen;
		count -= chunklen;
	}

	DEBUG("new length = %zd, length of tail chunk = %d", b->length, b->tail_block->data_end );
}

void lb_enqueue_str( LinkedBlocks b, const char *s )
{
	lb_enqueue( b, s, strlen(s) );
}

void lb_front( LinkedBlocks b, void **ptr, size_t *siz, size_t limit )
{
	*ptr = b->data + b->data_start;
	*siz = MIN( limit, b->data_end - b->data_start );
}

/* returns the new head of the linked block */
LinkedBlocks lb_dequeue( LinkedBlocks b, size_t limit, size_t *removed )
{
	struct LinkedBlockItem *head;
	int chunklen;
	*removed = 0;
	head = b;

	if ( head->data_start == head->data_end )
	{
		/* this should be a state maintained by this very function after
		 * returning, where the only possibility of an empty head block is
		 * when the whole queue is empty */
		ASSERT(head->next == NULL);
		return head;
	}

	DEBUG("trying to dequeue %zd bytes in LinkedBLock", limit);

	while ( *removed != limit )
	{

		chunklen = MIN ( (limit - *removed) , head->data_end - head->data_start );

		*removed += chunklen;
		head->data_start += chunklen;

		if ( head->data_start == head->data_end )
		{
			if ( head->next == NULL )
			{
				head->tail_block = head;
				head->data_start = 0;
				head->data_end = 0;
				head->next = NULL;
				head->length = 0;
				return head;
			}
			{
				struct LinkedBlockItem *t;
				head->next->tail_block = head->tail_block;
				head->next->length = head->length;
				t = head;
				head = head->next;
				free(t);
			}
		}
	}

	head->length -= *removed;

	return head;
}

void lb_delete( LinkedBlocks b )
{
	struct LinkedBlockItem *prev;

	while (b != NULL) {
		prev = b;
		b = prev->next;
		free(prev);
	}
}

int lb_is_empty( LinkedBlocks b )
{
	return b->length == 0;
}

int lb_length ( LinkedBlocks b )
{
	return b->length;
}

/* Push a pointer onto an array, resizing the array if necessary */
/* void ***array === Pointer to an array of pointers. */
void array_push(void ***array, int *len, int *siz, void *item)
{
	(*len)++;

	/* "if" is sufficient here since len can only be incremented by one, and we
	 * assume the values were consistent before pushing */
	if (*siz < *len) 
	{
		(*siz) *= 2;
		*array = realloc(*array, *siz);
	}

	(*array)[(*len)-1] = item;
}

/* returns true if string s has prefix prefix */
int prefix_cmp(const char *s, const char *prefix)
{
	return (strncmp(s, prefix, strlen(prefix)) == 0);
}

/* returns true if string s has prefix prefix (case insensitive) */
int prefix_icmp(const char *s, const char *prefix)
{
	return (strncasecmp(s, prefix, strlen(prefix)) == 0);
}

/* strict base-10 string-to-integer conversion */
enum result_t intval(const char *s, int *value)
{
	const char *c = s;
	int v = 0, k;
	while (*c != 0) 
	{
		if (v > INT_MAX / 10) return OVERUNDERFLOW;
		v = v * 10;

		k = *c - '0';
		if ( k < 0 || k > 9 ) return FAIL;

		if (v > INT_MAX - k) return OVERUNDERFLOW;
		v = v + k;

		c++;
	}

	*value = v;

	return SUCCESS;
}

/* convert slashes to backslashes, mainly for win32 */
void slash2backslash( const char *in_str, char *out_str )
{
	const char *r;
	char *w;
	for (r = in_str, w = out_str; *r != 0; r++, w++) 
		if (*r == '/') *w = '\\'; else *w = *r;
	*w = 0;
}

/* chop off trailing slash or backslash (in place) */
void chopslash ( char *s )
{
	int k;
	for (k = strlen(s); k > 0; k--)
	{
		if (s[k-1] == '\\') s[k-1] = 0;
		else if (s[k-1] == '/') s[k-1] = 0;
		else break;
	}
}


/* Assumption: path is forward slash based, even in win32. However, safety is
 * checked in somewhat different ways. We might want to change this behavior by
 * converting to backslashes before doing this check. */
int is_fs_safe_path( const char *path )
{
	int l = 0;
	int k;

	const char **it;

	char buf[10];

#ifdef WIN32
/* XXX: UNTESTED */
	/* I drew some help from: http://docs.info.apple.com/article.html?artnum=301956 */
	/* suggestions for better sources welcomed */

	const char *c;

	/* NOTE: ensure that these names do not exceed sizeof buf[]-2 above */
	const char *unsafe_names[] =
	{
		/* reserved names in windows. */
		"com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
		"lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
		"con", "nul", "prn", "aux",

		/* dont allow wriggling out of docroot by using .. */
		"..",

		NULL,
	};

	for (c = path; *c != 0; c++, l++)
	{
		// if (*c < 32) return False; // this line commented out since utf-8 paths seem to have char values < 32... (but is there any unsafe stuff here?)
		switch (*c)
		{
			case '"':
			case '\\': /* backslash is unsafe because at this point we haven't
						  converted slashes to backslashes yet, see function
						  description */
			case '<':
			case '>':
			case '?':
			case ':':
			case '*':
			case '|':
				return False;
			default:
				break;
		}
	}

	if (l == 0) return False;

	if (path[0] == ' ') return False;

	if (path[l-1] == '.' || path[l-1] == ' ') return False;

	if (l > MAX_PATH) return False;

#else /* ! WIN32 */

	l = strlen(path);

	/* NOTE: ensure that these names do not exceed sizeof buf[]-2 above */
	const char *unsafe_names[] =
	{
		/* dont allow wriggling out of docroot by using .. */
		"..",

		NULL,
	};

	if (l > PATH_MAX) return False; /* UNTESTED */

#endif

	for (it = unsafe_names; *it != NULL; it ++)
	{
		// DEBUG("checking for %s", *it);

		snprintf(buf, sizeof(buf), "/%s/", *it);
		k = strlen(buf);

		/* any more cases other than these 4? */

		/* as entire match */
		if (strcmp(path, *it) == 0) return False;

		/* as substring, eg: "abc/../xyz" */
		if (strstr(path, buf) != NULL) return False;

		/* as leading string with no leading slash */
		/* eg: "../xyz" */
		if (strncmp(path, buf+1, k-1) == 0) return False;

		/* as trailing string with no trailing slash */
		/* eg: "abc/.." */
		if (l - k + 1 < 0) continue;
		// DEBUG("x = '%s' '%s' '%d'", path + l - k + 1, buf, k - 1);
		if (strncmp(path + l - k + 1, buf, k - 1) == 0) return False;

		// DEBUG(".. looks good");
	}

	return True;
}

/* returns the integral value of a hex character */
int hexval(char c) 
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* returns [0-9A-F] according to k in [0,15] */
char inttohex(int k)
{
	ASSERT(k >= 0 && k < 16);
	if (k <= 9) return k+'0';
	return k-10+'A';
}

static char *__uri_encode_ptr = NULL;
static int __uri_encode_ptr_last_size = 0;

/* uri_encode a filename (the function name may be changed later if this code
 * can be used in other contexts.) */
/* Returns a static string allocated by the function, subsequent calls WILL
 * modify (or even free) the string, so strcpy it if not used for temporary
 * purposes */
char *uri_encode_filename( const char *s )
{
	const char *c;
	char *w;
	int l = 0;
	/* guess how many chars we need first */
	for (c = s; *c != 0; c++) 
	{
		switch(*c)
		{
			/* all reserved chars escaped here, see "Reserved Characters" rfc1630 */
			case '%':
			case '/': /* i'm not sure about this one */
			case '#':
			case '?':
			case '*':
			case '!':
				l+=3; /* "%XX" (3) */
				break;
			default:
				l++;
				break;
		}
	}

	if (__uri_encode_ptr == NULL)
	{
		__uri_encode_ptr_last_size = l + 1;
		__uri_encode_ptr = malloc(__uri_encode_ptr_last_size);
	}
	else
	{
		/* check whether we have to allocate */
		if (l >= __uri_encode_ptr_last_size)
		{
			__uri_encode_ptr_last_size = l + 1;
			__uri_encode_ptr = realloc(__uri_encode_ptr, __uri_encode_ptr_last_size);
		}
	}
	
	/* write to the buffer */
	for (c = s, w = __uri_encode_ptr; *c != 0; c++) 
	{
		switch(*c)
		{
			/* all reserved chars escaped here, see "Reserved Characters" rfc1630 */
			case '%':
			case '/': /* i'm not sure about this one */
			case '#':
			case '?':
			case '*':
			case '!':
				w[0] = '%';
				w[1] = inttohex((*c)/16);
				w[2] = inttohex((*c)%16);
				w+=3;
				break;
			default:
				w[0] = *c;
				w++;
				break;
		}
	}

	*w = 0;

	return __uri_encode_ptr;
}

/* tokenize the the big array */
void mime_init()
{
	const char *c;
	mime_num = 0;
	c = mime_dataraw;
	while ( c[0] != 0 ) /* check for the double NUL at the end */
	{
		mime_ext[mime_num] = c;
		c += strlen(c) + 1;
		mime_value[mime_num] = c;
		c += strlen(c) + 1;

		if (config_utf8text == True && strncmp(mime_value[mime_num], "text/", 5) == 0) {
			static const char *charset_utf8 = ";charset=utf-8";
			/* Note: leaky singletons */
			char *mime_with_utf8 = malloc(strlen(mime_value[mime_num]) + strlen(charset_utf8) + 1);
			strcpy(mime_with_utf8, mime_value[mime_num]);
			strcat(mime_with_utf8, charset_utf8);
			mime_value[mime_num] = mime_with_utf8;
		}

		/* save the pointer to text/html so we can use it conveniently later */
		if (strcmp(mime_ext[mime_num], "html") == 0) mime_HTML = mime_value[mime_num];

		mime_num++;
	}

	ASSERT(mime_HTML != NULL);
}

/* uses a static buffer */
char *log_date( time_t t )
{
	struct tm *tmp;
	tmp = localtime(&t);
	ASSERT(tmp != NULL); /* seems that there is no reason (at least in glibc
							docs) localtime will return NULL */

#ifdef WIN32 /* just don't show the timezone in windows... the name is toooo long, and it reportedly uses the codepage/locale of the system, without unicode... */
	strftime(buf256,sizeof(buf256),"%Y-%m-%d.%H:%M:%S", tmp);
#else
	strftime(buf256,sizeof(buf256),"%F.%H:%M:%S.%z", tmp);
#endif

	return buf256;
}

char *strint( int a ) { sprintf(buf256, "%d", a); return buf256; }
char *struint( unsigned int a ) { sprintf(buf256, "%d", a); return buf256; }
char *strlong ( long a ) { sprintf(buf256, "%ld", a); return buf256; }
char *strulong ( unsigned long a ) { sprintf(buf256, "%ld", a); return buf256; }
#ifdef WIN32
char *strulonglong ( unsigned long long a ) { sprintf(buf256, "%I64d", a); return buf256; }
#else
char *strulonglong ( unsigned long long a ) { sprintf(buf256, "%lld", a); return buf256; }
#endif


/* )** FUNCTION PROTOTYPES ** (*/

void http_process( struct Request *req );
enum result_t http_decode_uri_abs_path( const char *in_str, char *out_str,
		char **query_strings );

/* )******** IO WRAP ******* (*/
#define IO_NONBLOCK 0x1

static enum result_t io_errno;

enum filetype_t
{
	NORMAL,
	DIRECTORY,
	NOTFOUND,
	OTHER,
};
#ifdef WIN32

enum filetype_t io_filetype( const char * path )
{
	DWORD res;
	char realpath[MAX_PATH+1];
	WCHAR realpath_w[MAX_PATH+1];

	if ( strlen(path) >= sizeof(realpath) )
	{
		WARN("path too long for io_is_dir(): '%s'", path);
		return NOTFOUND;
	}

	slash2backslash( path, realpath );
	res = MultiByteToWideCharWrapper( CP_UTF8, MB_ERR_INVALID_CHARS, realpath, -1, realpath_w, sizeof(realpath_w) );
	if (res == 0)
	{
		DEBUG("error in utf-8 to WCHAR conversion");
		return NOTFOUND;
	}
	res = GetFileAttributesW( realpath_w );

	/* 0xFFFFFFFF is an error as per some old API docs, tested. */
	if ( res == INVALID_FILE_ATTRIBUTES ) return NOTFOUND;

	if (res & FILE_ATTRIBUTE_DIRECTORY) return DIRECTORY;
	if (res & FILE_ATTRIBUTE_NORMAL) return NORMAL;

	DWORD ign_mask = ~ ((DWORD) 0);
	/* files can be sparse, readonly, not-indexed, and archivable but still a "normal" file. */
	/* maybe also allow "compressed" ? */
	ign_mask = ign_mask & (~ FILE_ATTRIBUTE_SPARSE_FILE );
	ign_mask = ign_mask & (~ FILE_ATTRIBUTE_READONLY );
	ign_mask = ign_mask & (~ FILE_ATTRIBUTE_NOT_CONTENT_INDEXED );
	ign_mask = ign_mask & (~ FILE_ATTRIBUTE_ARCHIVE );

	if ( (res & ign_mask) == 0 ) return NORMAL;

	/* if there are other bits set, those are probably weirdo system/strange files. Just don't allow them... */
	return OTHER;
}
#else

enum filetype_t io_filetype( const char * path )
{
	struct stat s;
	int res;
	res = stat( path, &s );
	if (res != 0) return NOTFOUND;
	if (S_ISDIR(s.st_mode)) return DIRECTORY;
	if (S_ISREG(s.st_mode)) return NORMAL;
	return OTHER;
}


#endif


#ifdef WIN32
#define IO_OPEN_FILE_FAIL NULL
WCHAR path_w[MAX_PATH + 1];
file_t io_open_file( const char *path, unsigned int options )
{
	DWORD e;
	file_t f;
	DWORD flags = 0;
	HANDLE h;
	int res;

	if ( (options & IO_NONBLOCK) ) flags = FILE_FLAG_OVERLAPPED;

	ASSERT(flags != 0);

	ASSERT( strlen(path) <= MAX_PATH );
	res = MultiByteToWideCharWrapper( CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, path_w, sizeof(path_w) );

	h = CreateFileW( path_w, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, flags, NULL );

	DEBUG("handle = %x",  (unsigned int) h);

	/* XXX: there's gotta be more obscure errors here... */
	if ( h == INVALID_HANDLE_VALUE )
	{
		e = GetLastError();
		switch(e)
		{
			case ERROR_PATH_NOT_FOUND:
			case ERROR_FILE_NOT_FOUND:
				io_errno = FAIL_NOTFOUND;
				break;
			case ERROR_ACCESS_DENIED: /* FIXME: UNTESTED */
				io_errno = FAIL_ACCESS;
				break;
			default:
				WARN("CreateFile() returned unepxected 0x%lx", e);
				io_errno = FAIL_SYS;
				break;
		}

		return NULL;
	}
	else
	{
		f = malloc(sizeof(struct __file_t));
		f->open_options = options;
		f->async_working = False;
		f->async_offset = 0;
		f->h = h;
		io_errno = SUCCESS;
		return f;
	}

}
#else
#define IO_OPEN_FILE_FAIL (-1)
file_t io_open_file( const char *path, int options )
{
	file_t f;
	int e;

	int flags;

	flags = O_RDONLY;
		
	if (options & IO_NONBLOCK ) flags = flags | O_NONBLOCK;

	f = open( path, flags );

	if ( f == -1 )
	{
		e = errno;
		switch (e)
		{
			case EACCES:
				io_errno = FAIL_ACCESS;
				break;
			case ENOENT:
				io_errno = FAIL_NOTFOUND;
				break;
			default:
				WARN("open() returned -1 with error = %d", e);
				io_errno = FAIL_SYS;
				break;
		}
	}
	else
		io_errno = SUCCESS;

	return f;
}
#endif

#ifdef WIN32
#define IO_FILE_PROPERTIES_FAIL False
int io_file_properties( file_t f, struct file_properties *buf )
{
	LARGE_INTEGER siz;
	BOOL res;

	res = GetFileSizeEx( f->h, &siz );

	buf->size = siz.QuadPart;

	if (res == 0) return IO_FILE_PROPERTIES_FAIL;
	else return SUCCESS;
}
#else
#define IO_FILE_PROPERTIES_FAIL False
int io_file_properties( file_t f, struct file_properties *props )
{
	struct stat b;
	int res;
	res = fstat(f, &b);

	if (res == -1)
	{
		switch( errno )
		{
			case EACCES:
				io_errno = FAIL_ACCESS;
				break;
			case ENOENT: /*A component of the path path does not exist, or the path is an empty string.*/
			case ENOTDIR: /* A component of the path is not a directory.*/
				io_errno = FAIL_NOTFOUND;
				break;
#ifdef ELOOP
			case ELOOP: /* Too many symbolic links encountered while traversing the path. */
				break;
#endif
			case EBADF: /* filedes is bad. */
			case EFAULT: /*Bad address.*/
			case ENOMEM: /*Out of memory (i.e., kernel memory).*/
			default:
				WARN( WTFERR, errno );
				io_errno = FAIL_SYS;
				break;
		}

		return IO_FILE_PROPERTIES_FAIL;
	}
	
	props->size = b.st_size;
	return ! IO_FILE_PROPERTIES_FAIL;
}
#endif

#ifdef WIN32
#define IO_CLOSE_FILE_FAIL False
int io_close_file( file_t f )
{
	DWORD e;
	int ret;

	if ( f->async_working ) CancelIo( f->h );

	if ( ! CloseHandle( f->h ) ) 
	{
		e = GetLastError(); /* XXX: we may want to do some extra processing here */
		WARN("CloseHandle() failed with error %ld", e);
		io_errno = FAIL_SYS;
		ret = False;
	}
	else
	{
		io_errno = SUCCESS;
		ret = True;
	}

	free( f );

	return True;
}
#else
#define IO_CLOSE_FILE_FAIL False
int io_close_file( file_t f )
{
	int e;
	if ( close( f ) == -1 ) 
	{
		switch (e = errno)
		{
			default:
				io_errno = FAIL_SYS;
				WARN("close() failed with error %d", e);
				break;
		}

		return False;

	} else
		io_errno = SUCCESS;

	return True;
}
#endif

/* return of zero bytes read and io_errno = SUCCESS means EOF */
/* return of zero bytes read and io_errno = WOULD_BLOCK means what it says */
#ifdef WIN32
unsigned long io_read_file( file_t f, void *buf, size_t count )
{
	DWORD e;
	DWORD bytes_read;

	/* A previous async request was pending, now check whether it is completed */
	if ( f->async_working ) {
		err_t e;
		if ( GetOverlappedResult( f->h, &f->async, &bytes_read, FALSE ) )
		{
			/* The operation succeeded, presumably the data was read into buf (the function argument)  */
			io_errno = SUCCESS;
			f->async_working = False;
			f->async_offset += bytes_read;
			DEBUG( "got = %ld, total offset = %ld", bytes_read, f->async_offset );
			return bytes_read;
		}
		else
		{
			e = GetLastError();
			switch ( e )
			{
				case ERROR_IO_INCOMPLETE:
					DEBUG("the async operation still not yet done");
					io_errno = WOULD_BLOCK;
					return 0;
				case ERROR_HANDLE_EOF:
					DEBUG("got eof");
					io_errno = SUCCESS;
					return 0;
				default:
					WARN(WTFERR, e);
					io_errno = FAIL_SYS;
					return 0;
			}
		}
	}

	ASSERT( f->open_options & IO_NONBLOCK ); // this assertion is used because I removed some old code but I'm not sure the code paths are all eliminated correctly.
	{
		DEBUG("handle = %x", (unsigned int) f->h);
		memset( & f->async, 0, sizeof(f->async) );
		f->async.OffsetHigh = 0;
		f->async.Offset = f->async_offset;
		if ( ReadFile( f->h, buf, count, &bytes_read, &f->async ) )
		{
			DEBUG("not blocked, read %lu bytes", bytes_read);
			f->async_offset += bytes_read;
			return bytes_read;
		}
		else
		{
			e = GetLastError();
			switch (e)
			{
				case ERROR_HANDLE_EOF:
					DEBUG("got eof");
					io_errno = SUCCESS;
					return 0;
				case ERROR_IO_PENDING:
					f->async_working = True;
					DEBUG("would block");
					io_errno = WOULD_BLOCK;
					return 0;
				default:
					WARN(WTFERR, e);
					io_errno = FAIL_SYS;
					return 0;
			}
		}
	}
}
#else
unsigned long io_read_file( file_t f, void *buf, size_t count )
{
	ssize_t res;
	res = read( f, buf, count );

	if ( res == -1 )
	{
		switch( errno )
		{
			case EINTR: /* process interrupted, let's read again */
				return io_read_file( f, buf, count );
			case EAGAIN: /* a read would block, don't read again */
				io_errno = WOULD_BLOCK;
				break;
			case EIO: /* I/O error. */
				DEBUG("got EIO!");
				io_errno = FAIL_SYS;
				break;
			case EISDIR: /* fd refers to a directory. */
			case EBADF:  /* fd is not a valid file descriptor or is not open for reading. */
			case EFAULT: /* buf is outside your accessible address space. */
			case EINVAL: /* fd  is  attached  to  an  object which is unsuitable for reading; or the file was opened with the O_DIRECT flag, and either the address specified in buf, the value specified in count, or the current file offset is not suitably aligned. */
			default:
				io_errno = FAIL_SYS;
				WARN("read() unexpectedly returned %d", errno);
				break;
		}
		res = 0;
	}
	else
		io_errno = SUCCESS;

	return res;
}
#endif


#ifdef WIN32
#define IO_OPEN_DIR_FAIL NULL

char __io_open_dir_buf[MAX_PATH+2+1];
WCHAR __io_open_dir_buf_w[MAX_PATH+2+1];

/* FIXME: error handling, remember to set io_errno */
dir_t* io_open_dir( const char *path )
{
	int l;
	dir_t* ret;
	int res;
	ret = malloc(sizeof(dir_t));
	ret->nomorefiles = False;

	io_errno = FAIL_SYS;

	if (ret == NULL) return IO_OPEN_DIR_FAIL;

	l = strlen(path);
	if (l > MAX_PATH) return IO_OPEN_DIR_FAIL;

	strcpy(__io_open_dir_buf, path);
	chopslash(__io_open_dir_buf);
	strcat(__io_open_dir_buf, "\\*");

	res = MultiByteToWideCharWrapper( CP_UTF8, MB_ERR_INVALID_CHARS, __io_open_dir_buf, -1, __io_open_dir_buf_w, sizeof(__io_open_dir_buf_w) );
	if ( res == 0 ) {
		DEBUG("conversion from utf-8 to WCHAR failed");
		return IO_OPEN_DIR_FAIL;
	}

	DEBUG("find path = '%ls'", __io_open_dir_buf_w);

	ret->h = FindFirstFileW( __io_open_dir_buf_w, &ret->ffd );
	if (ret->h == INVALID_HANDLE_VALUE) return IO_OPEN_DIR_FAIL;

	DEBUG("FindFirstFile found '%ls'", ret->ffd.cFileName);

	io_errno = SUCCESS;
	return ret;
}

#else
#define IO_OPEN_DIR_FAIL NULL

dir_t* io_open_dir( const char *path )
{
	dir_t *d;
	d = opendir( path );
	if (d == NULL)
	{
		switch (errno)
		{
			case EACCES:
				io_errno = FAIL_ACCESS;
				break;
			case ENOTDIR:
			case ENOENT:
				io_errno = FAIL_NOTFOUND;
				break;
			default:
				io_errno = FAIL_SYS;
				break;
		}

		return IO_OPEN_DIR_FAIL;
	}

	io_errno = SUCCESS;
	return d;
}

#endif

/* FIXME: error handling */
#ifdef WIN32
#define IO_READ_DIR_FAIL NULL
/* this is going to be a utf8 string, which means it *might* expand to four bytes per wchar... */
char __io_read_dir_buf[MAX_PATH*4+1];
WCHAR __io_read_dir_buf_w[MAX_PATH+1];

const char *io_read_dir( dir_t *dir )
{
	int res;

	if ( dir->nomorefiles ) return NULL;

	ASSERT(wcslen(dir->ffd.cFileName) <= MAX_PATH);
	wcscpy(__io_read_dir_buf_w, dir->ffd.cFileName);

	io_errno = SUCCESS;

	if (!FindNextFileW(dir->h, &dir->ffd))
	{
		if (GetLastError() != ERROR_NO_MORE_FILES)
		{
			WARN("FindNextFile() failed!");
			/* FIXME: the better way is probably to actually allow the
			 * return value, and *SAVE* the error for the next call... */
			io_errno = FAIL_SYS;
			return IO_READ_DIR_FAIL;
		}

		dir->nomorefiles = True;
	}
	else
		DEBUG("FindNextFile found '%ls'", dir->ffd.cFileName);

	res = WideCharToMultiByte( CP_UTF8, 0, __io_read_dir_buf_w, -1, __io_read_dir_buf, sizeof(__io_read_dir_buf), NULL, NULL);

	if ( res == 0 ) WARN( "Conversion from WCHAR to UTF-8 encoded string failed" );

	return __io_read_dir_buf;
}

#else
#define IO_READ_DIR_FAIL NULL
const char *io_read_dir( dir_t *dir )
{
	struct dirent *de;
	de = readdir( dir );
	io_errno = SUCCESS; /* assume success. I don't see any way to check in the man page */
	if (de == NULL) return IO_READ_DIR_FAIL;
	return de->d_name;
}
#endif

/* FIXME: error handling */
#ifdef WIN32
#define IO_CLOSE_DIR_FAIL False

int io_close_dir( dir_t *dir )
{
	int ret;
	if (FindClose(dir->h)) ret = !IO_CLOSE_DIR_FAIL;
	else ret = IO_CLOSE_DIR_FAIL;
	free(dir);
	return ret;
}

#else
#define IO_CLOSE_DIR_FAIL False

int io_close_dir( dir_t *dir )
{
	if ( closedir( dir ) == -1 ) return IO_CLOSE_DIR_FAIL;
	return (! IO_CLOSE_DIR_FAIL );
}

#endif

/* )******** REQUEST ******* (*/

#ifdef WIN32
int find_request_idx_by_fd( int fd )
{
	int k;
	k = fd % MAX_FILE_DESCRIPTORS;
	while (requests[k] == NULL || requests[k]->fd != fd)
	{
		k = (k+1) % MAX_FILE_DESCRIPTORS;
		if (k == fd % MAX_FILE_DESCRIPTORS) ASSERTM(EXIT_BUG, "cannot find request with specified fd");
	}
	return k;
}
#else
#define find_request_idx_by_fd(fd) (fd)
#endif

#ifdef WIN32
int find_empty_request_idx (int fd)
{
	int k;
	k = fd % MAX_FILE_DESCRIPTORS;
	while (requests[k] != NULL)
	{
		k = (k+1) % MAX_FILE_DESCRIPTORS;
		if (k == fd % MAX_FILE_DESCRIPTORS) return -1;
	}
	return k;
}
#else
#define find_empty_request_idx(fd) ((fd)<(MAX_FILE_DESCRIPTORS)?(fd):-1)
#endif

/* creates a new Request object, puts it into the requests[] array
 * and returns the object. May return NULL on errors */
struct Request* new_request(int fd, struct sockaddr_in *remote_addr)
{
	struct Request *req;
	int idx;

	DEBUG("Creating new request");

	if ( (idx = find_empty_request_idx(fd)) == -1 )
	{
		WARN( "file descriptor limit exceeded! fd = %d", fd );
		return NULL;
	}

	req = requests[idx] = malloc(sizeof(struct Request));

	if (req == NULL) /* UNTESTED */
	{
		CRIT("cannot create request object: malloc returned NULL");
		return NULL;
	}

	req->fd = fd;

	req->i_buffer = (char*) malloc(BUF_CHUNK);
	req->i_buffer_siz = BUF_CHUNK;
	req->i_buffer_len = 0;

	req->o_queue = lb_new();
	
	req->f_buffer = NULL; /* not every request is a static file! */

	req->h_buffer = (char*) malloc(BUF_CHUNK);
	req->h_buffer_siz = BUF_CHUNK;
	req->h_buffer_len = 0;
	req->h_sent = 0;

	req->last_read = req->i_buffer;

	req->had_enough_input = False;
	req->h_done = False;
	req->o_done = False;

	req->num_lines = 0;
	req->lines_siz = 32;
	req->lines = (char **) malloc(req->lines_siz * sizeof(char*));
	req->processed_lines = 0;

	req->method = UNKNOWN;
	req->request_uri = NULL;

	req->done_tokenizing_headers = False;
	req->is_simple = False;

	req->ver_major = -1;
	req->ver_minor = -1;
	req->resp_status = 0;

	req->content_type = NULL;
	req->user_agent = NULL;
	req->referer = NULL;

	req->fhandle = 0;

	memcpy( & req->remote_addr, remote_addr, sizeof(struct sockaddr_in) );

	DEBUG("done creating new request");

	return req;
}

/* free buffers/arrays allocated in new_request(), and free the request object
 * itself */
void delete_request(struct Request *req)
{
	DEBUG("delete request %d", req->fd);
	if ( req->f_buffer != NULL ) free( req->f_buffer );
	free(req->i_buffer);
	lb_delete(req->o_queue);
	free(req->h_buffer);
	free(req->lines);
	free(req);
}

/* close the request connection and cleanup any structures related to the
 * request */
void close_request(struct Request *req) 
{
	int res;
	int idx;
	DEBUG("closing connection of fd = %d", req->fd);

	idx = find_request_idx_by_fd(req->fd);

	/* unregister request from global requests array (so server_select() will
	 * no longer consider to select() it) */
	ASSERT(requests[idx] == req);
	requests[idx] = NULL;

	/* close the socket */
	res = close(req->fd);
	if (res != 0) WARN("Error encountered while trying to close()!");

	/* close the file */
	if ( req->fhandle != 0 && io_close_file( req->fhandle ) == IO_CLOSE_FILE_FAIL )
		WARN("io_close_file() failed");

	/* free up memory */
	delete_request(req);
}


/* clear any pending header contents (if headers not already sent) */
void request_clear_header(struct Request *req)
{
	ASSERTM(req->h_sent == 0,
			"requested to clear headers but headers already sent!");
	if (req->h_buffer_len == 0) return;
	req->h_buffer_len = 0;
}

/* add contents to the header buffer for pending send() */
void request_enqueue_header(struct Request *req, const void *ptr, size_t len)
{
	if (req->is_simple) return; /* don't do anything if the request is simple
								   because simple responses do not have headers
								   as per rfc1945 */

	req->h_buffer_len += len;

	/* XXX: unless we have untrusted code that might bloat up the header buffer
	 * we don't really need to check whether the header buffer is too large...
	 * */

	/* expand buffer size if necessary */
	while (req->h_buffer_siz < req->h_buffer_len ) 
	{
		req->h_buffer_siz *= 2;
		req->h_buffer = realloc( req->h_buffer, req->h_buffer_siz );
	}

	/* copy the data to request's input buffer for later processing */
	memcpy( req->h_buffer + req->h_buffer_len - len,  /* old length */
			ptr,
			len );
}

/* helpful utility for enqueueing strings to header. not implemented for
 * request_enqueue_content because the contents are likely to be binary as well
 * (but headers are probably ASCII and most likely short C strings) */
void request_enqueue_header_str(struct Request *req, const char *s)
{
	request_enqueue_header(req, s, strlen(s));
}

void request_finalize_header( struct Request *req )
{
	if (req->h_done) {
		WARN("request_finalize_header called more than once");
		return;
	}
	request_enqueue_header( req, "\r\n", 2 );
	req->h_done = True;
}

/* dump some contents of the file into the Request memory structure, to be
 * emitted by socket code when the time comes */
enum result_t request_dump_file(struct Request *req )
{
	enum result_t ret;
	file_t f;
	unsigned long got = 0;
	int rounds = MAX_READ_ROUNDS;
	
	f = req->fhandle;

	DEBUG("reading...");

	while (rounds--)
	{
		if ( lb_length( req->o_queue ) >= MAX_OUTPUT_QUEUE_SIZE ) return CALL_AGAIN;
		got = io_read_file( f, req->f_buffer, BUF_CHUNK );
		if (got == 0) break;
		lb_enqueue( req->o_queue, req->f_buffer, got );
	}


	if (got == 0)
	{
		switch (io_errno)
		{
			case WOULD_BLOCK:
				DEBUG("a subsequent read would block");
				return WOULD_BLOCK;

			case FAIL_SYS:
				WARN("io_read_file failed");
				ret = FAIL_SYS;
				break;

			case SUCCESS:
				ret = SUCCESS;
				break;

			default:
				DIE( EXIT_BUG, ROGUE );
				break;
		}

		if ( io_close_file( f ) == IO_CLOSE_FILE_FAIL )
			WARN("io_close_file() failed");

		req->fhandle = 0;

		req->o_done = True;

		return ret;
	}

	/* got != 0, means rounds is exhausted */

	return CALL_AGAIN;
}

/* FIXME: some files should not be read! (eg stuff in /dev, pipes, etc.)
 * fstat() is your friend */
enum result_t request_start_stream_file( struct Request *req, const char *path )
{
	file_t f;
	DEBUG("trying to open '%s'", path);
	f = io_open_file( path, IO_NONBLOCK );
	if ( f == IO_OPEN_FILE_FAIL ) return io_errno;
	DEBUG("good");

	req->fhandle = f;

	req->f_buffer = malloc(BUF_CHUNK);

	request_dump_file( req ); /* dump a first chunk */
	return SUCCESS;
}

enum result_t request_list_directory( struct Request *req, const char *path ) 
{
	enum result_t ret = UNKNOWN_RESULT;
	char *decoded_path;
	const char *filename;
	dir_t *dir;

	dir = io_open_dir( path );
	if (dir == IO_OPEN_DIR_FAIL ) return FAIL_SYS;

	decoded_path = malloc( strlen(req->request_uri) + 1 );
	if (http_decode_uri_abs_path( req->request_uri, decoded_path, NULL ) != SUCCESS)
		return FAIL_SYS;

	lb_enqueue_str( req->o_queue, "<html><head><title>Index of " );
	lb_enqueue_str( req->o_queue, decoded_path );
	lb_enqueue_str( req->o_queue, "</title></head><body><h1>Index of " );
	lb_enqueue_str( req->o_queue, decoded_path );
	lb_enqueue_str( req->o_queue, "</h1><ul>\n" );

	while ( ( filename = io_read_dir( dir ) ) != IO_READ_DIR_FAIL )
	{
		lb_enqueue_str( req->o_queue, "<li><a href=\"./" );
		lb_enqueue_str( req->o_queue, uri_encode_filename(filename) ); 
		lb_enqueue_str( req->o_queue, "\">" ); 
		lb_enqueue_str( req->o_queue, filename ); /* FIXME: we need html entity escapes here */
		lb_enqueue_str( req->o_queue, "</a></li>\n" );
	}

	if ( io_errno == SUCCESS ) ret = SUCCESS;
	else ret = FAIL_SYS;

	lb_enqueue_str( req->o_queue, "</ul><p><i>Server: " ONEHTTPD_VERSION_STRING_FULL "</i></p><script type='text/javascript'><!--\nfunction cmp(a,b) { if (a > b) return 1; if (a === b) return 0; return -1; } window.onload = function() { var t = document.getElementsByTagName('UL')[0]; var x = t.childNodes; var l = []; for (var i = 0; i < x.length; i++) { if (x[i].tagName && x[i].tagName.toUpperCase() === 'LI') l.push(x[i]); } l.sort(function (a, b) { return cmp(a.firstChild.firstChild.nodeValue, b.firstChild.firstChild.nodeValue); }); for (var i = 0; i < l.length; i++) { t.removeChild(l[i]); t.appendChild(l[i]); } };\n--></script></body></html>\n" );

	io_close_dir( dir );

	req->o_done = True;

	return ret;
}

void request_set_content_type( struct Request *req, const char *path )
{
	char *dot;
	char *sep;
	char ext[16]; /* well extensions aren't greater than 15 chars... are they? are they? */
	int i,l;

	dot = strrchr(path, '.');
	sep = strrchr(path, '/'); /* WARNING: could be a backslash later on win32
								 systems... TODO: use a generic SEP definition
								 in the headers */

	if (dot == NULL) return;
	if (sep != NULL && sep > dot) return; /* if path separator is closer to the
											 end than the dot, means the dot is
											 part of the path leading to the
											 dir of the file instead part of
											 the filename */
	dot++; /* start from char after the dot */

	l = strlen(dot);
	if (l >= 16 || l == 0) return;

	for (i = 0 ; i < l ; i ++ ) ext[i] = tolower(dot[i]);
	ext[l] = 0;

	for ( i = 0 ; i < mime_num; i++ )
	{
		if (strcmp(ext, mime_ext[i]) == 0)
		{
			req->content_type = mime_value[i];
			return;
		}
	}

}

/* )******* WSOCKINIT ****** (*/

#ifdef WIN32
enum result_t wsockinit()
{
	INFO("Initializing winsock...");
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;
 
	wVersionRequested = MAKEWORD( 1, 1 );
 
	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) return FAIL;
 
	/* Confirm that the WinSock DLL supports 1.1 */
	if ( LOBYTE( wsaData.wVersion ) != 1 || HIBYTE( wsaData.wVersion ) != 1 )
	{
		WSACleanup( );
		return FAIL;
	}
 
	return SUCCESS;
}
#else
/* nothing to do for POSIX systems which support BSD sockets */
enum result_t wsockinit() { return SUCCESS; }
#endif

/* )******** SOCKET ******** (*/

int server_listen()
{
	int res;
	struct sockaddr_in listen_sa;
	int sock;
	int reuse_addr = 1;
	
	sock = socket( PF_INET, SOCK_STREAM, 0 );
	ASSERTM(sock != -1, "Error creating socket");

	res = setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, (void *) &reuse_addr, sizeof( reuse_addr ) );
	ASSERTM( res == 0, "Cannot set socket options!" );

	/* TODO: use the bind address instead */
	listen_sa.sin_addr.s_addr = htonl( INADDR_ANY );
	listen_sa.sin_port = htons( config_bind_port );
	listen_sa.sin_family = AF_INET;

	res = bind( sock, (struct sockaddr *) &listen_sa, sizeof( listen_sa ) );
	ASSERTM(res == 0, "Cannot bind to %s:%d", config_bind_addr, config_bind_port);
	res = listen( sock, MAX_FILE_DESCRIPTORS );
	ASSERTM(res == 0, "Cannot listen on %s:%d", config_bind_addr, config_bind_port);
	return sock;

}

int server_accept(int listen_sock, struct sockaddr_in *remote_sin)
{
	int conn;
	socklen_t remote_sin_len;

	remote_sin_len = sizeof( *remote_sin );
	conn = accept(listen_sock, (struct sockaddr *) remote_sin, &remote_sin_len );

	if (conn == -1) /* UNTESTED */
	{
		CRIT("accept() failed!");
		return -1;
	}

	DEBUG( "Accepted a connection from %lx",
			(unsigned long) remote_sin->sin_addr.s_addr );

	return conn;
}



/* Returns SUCCESS or FAIL_SYS */
enum result_t encode_and_send( struct Request *req )
{
	void *buf;
	size_t got;
	ssize_t sent;
	size_t removed;

	/* Slow */
	lb_front( req->o_queue, &buf, &got, BUF_CHUNK );

	/* FIXME error handling */
	DEBUG("attempt to send to socket %d", req->fd);
	sent = send( req->fd, buf, got, 0 );
	DEBUG("sent %ld bytes", sent);
	ASSERT(sent != 0); /* supposedly we used a select() to make sure we can send things */
	if (sent == SOCKET_ERROR) {
		DEBUG("socket error");
		return FAIL_SYS;
	}

	req->o_queue = lb_dequeue( req->o_queue, got, &removed );

	/* we just grabbed 'got' bytes from the queue, so we should be able to remove it */
	ASSERT( got == removed );

	return SUCCESS;
}

void server_select(int listen_sock)
{
	int i;
	int nfds = 0;
	int res;
	struct Request *req;
	char buf[BUF_CHUNK];
	struct sockaddr_in remote_sin;
	struct timeval tv;
	err_t err;

	fd_set fds_r;
	fd_set fds_w;
	FD_ZERO( &fds_r );
	FD_ZERO( &fds_w );
	tv.tv_sec = 0;
	tv.tv_usec = 0;

	FD_SET( listen_sock, &fds_r );
	if (nfds < listen_sock) nfds = listen_sock;

	/* FD_SET section */
	for (i = 0 ; i < MAX_FILE_DESCRIPTORS; i++)
	{
		req = requests[i];
		if (req == NULL) continue;
		if (nfds < req->fd) nfds = req->fd;

		res = 0; /* whether it has expired */

		if ( ! req->had_enough_input )
		{
			DEBUG("adding fd = %d to select fds for recv", req->fd);
			FD_SET( req->fd, &fds_r );
			res = 1;
		}

		if (
				(req->h_done && req->h_sent != req->h_buffer_len) ||
				(
				 (req->h_done && req->h_sent == req->h_buffer_len) &&
				 ( ! lb_is_empty( req->o_queue ) )
				)
		   )
		{
			DEBUG("adding fd = %d to select fds for send", req->fd);
			DEBUG("queue has length %d", lb_length( req->o_queue ) );
			FD_SET( req->fd, &fds_w );
			res = 1;
		}

		if ( req->had_enough_input && ! req->o_done && lb_length(req->o_queue) < MAX_OUTPUT_QUEUE_SIZE )
		{
			tv.tv_usec = 10000; /* FIXME: use some dyanmic self adjusting methods */
		}

		/* nothing to read, nothing to write, nothing pending to write */
		if (res == 0 && req->o_done ) 
		{
			close_request( req );
		}

	}

	res = select( nfds + 1, &fds_r, &fds_w, NULL, (tv.tv_usec? &tv : NULL) );
	ASSERTM( res != -1, "select() returned -1!" );

	DEBUG("select returned %d", res);

	if ( FD_ISSET( listen_sock, &fds_r ) ) 
	{
		res = server_accept( listen_sock, &remote_sin );
		if (res != -1)
		{
			req = new_request( res, &remote_sin );

			/* if request object cannot be created (either due to memory error
			 * or fds used up) */
			if (req == NULL) close( res ); /* UNTESTED */
		}
	}

	for (i = 0 ; i < MAX_FILE_DESCRIPTORS; i++)
	{
		req = requests[i];
		if (req == NULL) continue;

		if (FD_ISSET( req->fd, &fds_r )) 
		{
			/* TODO: use MSG_DONTWAIT, but dunno what's the param for win32 */
			res = recv( req->fd, buf, sizeof(buf), 0 );

			if (res == -1)
			{
				err = GETERROR();
				switch (err)
				{
#ifdef WIN32
					case WSAECONNRESET: /* what's the diff between a "normal" close from the other side??? */
						WARN("Connection of %d (forcibly) reset by peer", req->fd);
						close_request( req );
						continue;
#endif
					/* FIXME: much more to be done here! But I don't know what errors to look for! (esp for win32) */
					default:
						DIE( EXIT_BUG, WTFERR, err );
						break;
				}
			}

			if (res == 0) 
			{
				close_request( req );
				continue;
			}

			req->i_buffer_len += res;

			/* basic safeguard against DDOS */
			if (req->i_buffer_len > MAX_REQUEST_SIZE)
			{
				close_request( req );
				continue;
			}

			/* expand buffer size if necessary */
			/* (the +1 is to allow things such as null terminating the request
			 * for string operations, and having a safe "buffer" to prevent
			 * overflows) */
			while (req->i_buffer_siz < req->i_buffer_len + 1) 
			{
				req->i_buffer_siz *= 2;
				req->i_buffer = realloc( req->i_buffer, req->i_buffer_siz );
			}

			/* copy the data to request's input buffer for later processing */
			memcpy( req->i_buffer + req->i_buffer_len - res,  /* old length */
					buf,
					res );

			req->i_buffer[req->i_buffer_len] = 0;

			http_process( req );
		}

		if (FD_ISSET( req->fd, &fds_w ))
		{
			/* FIXME: use MSG_DONTWAIT */
			/* FIXME: more extensive check for errors when send returns -1 (or maybe 0?) */

			if ( (req->h_done && req->h_sent != req->h_buffer_len) )
			{
				res = send( req->fd, req->h_buffer + req->h_sent,
						req->h_buffer_len - req->h_sent, 0 );
				DEBUG("send returned %d", res);
				if ( res == SOCKET_ERROR )
				{
					close_request(req);
					continue;
				}
				req->h_sent += res;
			}

			if (req->h_done && req->h_sent == req->h_buffer_len && ! lb_is_empty( req->o_queue ) )
			{
				if ( encode_and_send( req ) != SUCCESS )
				{
					close_request(req);
					continue;
				}
			}

		}

		if ( req->had_enough_input && ! req->o_done )
		{
			request_dump_file( req );
		}
	}
}

/* )********* HTTP ********* (*/
/* Reference: http://tools.ietf.org/html/rfc1945#section-3.2.1 */

/* This function *only* *attempts* to decode "abs_path", and most probably not
 * correctly */
/* out_str should be allocated by caller. the resulting string will not be
 * longer then in_str, hence allocating strlen(in_str)+1 will be fine */
/* TODO: query strings not implemented yet */
enum result_t http_decode_uri_abs_path( const char *in_str, char *out_str,
		char **query_strings )
{
	const char *r;
	char *w;
	int k;

	for (r = in_str, w = out_str; *r != 0; r++, w++)
	{
		char c = *r;
		if (c < 32) c = 0; /* unsafe, deal with them together */
		switch (c)
		{
			/* unsafe! */
			case '\0':
			case '<':
			case '>':
			case ' ':
			case '#':
			case '"':
				DEBUG( "unsafe character encountered %d (%c)", *r, *r );
				return FAIL;
			case '%':
				r++;
				if (*r == 0) return FAIL;
				if (!ISHEX(*r)) return FAIL;
				k = hexval(*r) * 16;

				r++;
				if (*r == 0) return FAIL;
				if (!ISHEX(*r)) return FAIL;
				k += hexval(*r);

				*w = k;
				break;
			/* TODO: read the rfcs carefully. there should be something more? */
			default:
				*w = *r;
				break;
		}
	}

	*w = 0;

	return SUCCESS;
	
}

/* based on rfc1630 */
int http_valid_raw_uri( const char *s )
{
	if (*s == 0) return False;

	for (; *s != 0 ; s++) 
	{
		if (*s >= 0 && *s < 32) return False; /* control characters */

		switch (*s)
		{
			case ' ': /* space */
				return False;

			case '%':
				if (s[1] == 0 || s[2] == 0) return False;
				if (! ISHEX(s[1]) ) return False;
				if (! ISHEX(s[2]) ) return False;
				/* um, we can optimize a bit by s+=2 here */
				break;

			default:
				break;
		}
	}
	return True;
}


/* Reference: Section 5 of RFC1945: http://tools.ietf.org/html/rfc1945#section-5.1 */
/*
 * The following fields will be set by this function:
 * - enum http_method method
 * - char *request_uri
 * - char is_simple
 * - int ver_major
 * - int ver_minor
 */
enum result_t http_parse_request_line( struct Request *req ) 
{ /* atomic logic { */
	char *a, *b;

	if (req->processed_lines > 0) return ALREADY_DONE;
	if (req->num_lines == 0) return NEED_MORE;

	/* tokenize request method */
	a = req->lines[0];
	if (prefix_cmp(a, "GET ")) req->method = GET;
	if (prefix_cmp(a, "POST ")) req->method = POST;
	if (prefix_cmp(a, "HEAD ")) req->method = HEAD;
	if (req->method == UNKNOWN) return FAIL;

	b = strchr( a, ' ' );
	if (b == NULL) return FAIL;
	*b = 0;  /* request method can now be accessed through the req->lines[0] pointer */

	/* tokenize url */
	a = b + 1;
	req->request_uri = a;

	if (a[0] == ' ') return FAIL; /* double space after method */

	b = strchr( a, ' ' );
	if (b == NULL)
	{
		req->is_simple = True;
		req->ver_major = 0;
		req->ver_minor = 9;
	}
	else
	{
		req->is_simple = False;
		*b = 0;

		/* check for HTTP/X.Y string */
		a = b + 1;
		if (!prefix_cmp(a, "HTTP/")) return FAIL;
		a+=5;

		/* use intval() to grab the HTTP version number */
		b = strchr( a, '.' );
		if (b == NULL) return FAIL;
		if (a == b) return FAIL;
		*b = 0;
		if ( intval(a, &req->ver_major ) != SUCCESS ) return FAIL;
		a = b+1;
		if ( intval(a, &req->ver_minor ) != SUCCESS ) return FAIL;
	}

	DEBUG("checking whether '%s' is a valid uri", req->request_uri);
	if (!http_valid_raw_uri(req->request_uri))
	{
		req->request_uri = NULL;
		return FAIL;
	}

	req->processed_lines++;
	return SUCCESS;

/* } */ }

const char *http_get_status_code_desc( int status_code )
{
	const char **p;
	for (p = http_code_desc; *p != NULL; p++)
	{
		if ( ((long) p[0]) == status_code ) /* WARNING: pointer casting magic.. */
			return p[1];
	}

	DIE(EXIT_BUG, "attempted to find status code %d which does not exist", status_code );
}


void http_set_status_line( struct Request *req, int status ) 
{
	ASSERT( req->h_buffer_len == 0 );
	snprintf(buf256, sizeof(buf256), "HTTP/1.0 %d %s\r\n", status,
			http_get_status_code_desc(status) );
	request_enqueue_header_str( req, buf256 );

	req->resp_status = status;
}


/* simple static file serving routine */
/* returns a HTTP response code */
int http_execute_get_basic_filesystem( struct Request *req,
		const char *decoded_path )
{
	enum result_t res, tmp;
	char *full_path = NULL;
	enum filetype_t filetyperesult;

	if ( ! is_fs_safe_path( decoded_path ) ) 
	{
		WARN( "unsafe fs request encountered for path '%s'", decoded_path );
		return HTTP(404); /* pretend it doesn't exist if path is not safe */
	}

	/* generate full path to be accessed by file system routines */
	/* may be a "relative" path if DOCROOT is relative */
	/* XXX: make sure this is enough... */
	full_path = malloc( strlen(config_doc_root) + 1 + strlen(decoded_path) + strlen("index.html") + 1 );

	/* full_path = chopslash(config_doc_root) + '/' + decoded_path */
	strcpy(full_path, config_doc_root);
	chopslash(full_path); /* strip away extra trailing slashes */
	if (decoded_path[0] != '/')
		strcat(full_path, "/"); /* ensure at least one slash after the docroot */
	strcat(full_path, decoded_path);
	DEBUG("full path = '%s'", full_path);


	filetyperesult = io_filetype( full_path );

	if ( filetyperesult == DIRECTORY )
	{
		/* do a redirection for requests without trailing slash */
		if ( full_path[strlen(full_path)-1] != '/' ) 
		{
			res = HTTP(301);
			http_set_status_line( req, HTTP(301) );
			request_enqueue_header_str( req, "Content-Length: 0\r\n");
			request_enqueue_header_str( req, "Location: " );
			request_enqueue_header_str( req, req->request_uri );
			request_enqueue_header_str( req, "/\r\n" );
			req->o_done = True; /* there is no output */
		}
		else 
		{
			/* try concatenating index.html and see whether that works */
			/* we assume there's a trailing slash for full_path, so all's good */
			strcat(full_path, "index.html");

			tmp = request_start_stream_file( req, full_path );
			if ( tmp == SUCCESS )
			{
				req->content_type = mime_HTML;
				res = HTTP(200);
			}
			else
			{
				/* restore original full path */
				full_path[strlen(full_path)-strlen("index.html")] = 0;

				DEBUG("trying to list directory: '%s'", full_path);

				/* try to list directory if configured to do so */
				if (! config_list_directories )
				{
					res = HTTP(403);
				}
				else
				{
					/* TODO: we need to handle more stuff here */
					if ( request_list_directory( req, full_path ) == SUCCESS )
					{
						req->content_type = mime_HTML;
						res = HTTP(200);
					}
					else
						res = HTTP(500);
				}
			}
		}
	}
	else if ( filetyperesult == NORMAL )
	{
		switch ( request_start_stream_file( req, full_path ) )
		{
			case SUCCESS:
				/* add content type */
				request_set_content_type( req, full_path );
				res = HTTP(200);
				break;
			case FAIL_ACCESS:
				res = HTTP(403);
				break;
			case FAIL_NOTFOUND:
				res = HTTP(404);
				break;
			default:
				res = HTTP(500);
				break;
		}
	}
	else
	{
		res = HTTP(404);
	}


	if (full_path != NULL) free(full_path);

	return res;
}

int http_execute_get_dummy( struct Request *req )
{
	int printed;

	ASSERT( lb_length( req->o_queue ) == 0 );
	ASSERT( req->o_done == False );
	ASSERT( req->h_sent == False );

	request_enqueue_header_str( req, "Content-Type: text/html\r\n" );
	printed = snprintf( buf256, sizeof(buf256),
			"<html><head><title>Dummy Page</title></head>"
			"<body><h1>Dummy Page</h1><p>This is a dummy page for onehttpd.</p></body></html>" );
	lb_enqueue( req->o_queue, buf256, printed );
	req->o_done = True;
	return HTTP(200);
}

void http_boilerplate_response( struct Request *req, int status_code )
{
	const char *desc;
	int ret;

	req->had_enough_input = True;

	request_clear_header( req );
	ASSERT( lb_length( req->o_queue) == 0 );

	desc = http_get_status_code_desc( status_code );

	http_set_status_line( req, status_code );
	request_enqueue_header_str( req, "Content-Type: text/html\r\n" );

	ret = snprintf(
			buf256,
			sizeof(buf256),
			"<html><head><title>%d - %s</title></head>"
			"<body><h1>%d - %s</h1></body></html>", 
			status_code, desc,
			status_code, desc );

	lb_enqueue( req->o_queue, buf256, ret );

	req->o_done = True;
}

/* HTTP workhorse, called after everything is read */
/* currently the request is deemed "done" after return */
/* TODO: this function probably sorta blocks, might try to chunk it up a bit */
void http_execute_get( struct Request *req ) 
{
	char *decoded_path = NULL;
	int res;

	do
	{
		decoded_path = malloc( strlen(req->request_uri) + 1 );
		res = http_decode_uri_abs_path( req->request_uri, decoded_path, NULL );
		if (res != SUCCESS)
		{
			res = HTTP(400);
			break;
		}

		DEBUG("decoded path = '%s'", decoded_path);

		/* we insert dynamic stuff here */
		if ( config_dummy )
		{
			res = http_execute_get_dummy( req );
		}
		else
		{
			res = http_execute_get_basic_filesystem( req, decoded_path );
		}

	} while (False);

	switch (res) 
	{
		case HTTP(200):
			{

				request_clear_header( req );
				http_set_status_line( req, HTTP(200) );
				if (req->content_type)
				{
					request_enqueue_header_str( req, "Content-Type: " );
					request_enqueue_header_str( req, req->content_type );
					request_enqueue_header_str( req, "\r\n" );
				}

				request_enqueue_header_str( req, "Content-Length: " );
				if ( req->fhandle != 0 )
				{
					struct file_properties props;
					io_file_properties( req->fhandle, &props ); // FIXME: deal with failure
					request_enqueue_header_str( req, strulonglong( props.size ) );
				}
				else /* eg. the case for directory listings */
				{
					request_enqueue_header_str( req, strulong( lb_length( req->o_queue ) ) );
				}

				request_enqueue_header_str( req, "\r\n");
			}
			break;
		case HTTP(301):
			/* nothing to do for redirects since the contents are not static */
			break;

		case HTTP(400):
		case HTTP(403):
		case HTTP(404):
		case HTTP(500):
			http_boilerplate_response( req, res );
			break;

		default:
			DIE(EXIT_BUG, "http_execute_get_basic_filesystem returned unexpected value %d", res);
			break;
	}

	if (decoded_path != NULL) free(decoded_path);
}

/* uses a static buffer */
char *http_date( time_t t )
{
	struct tm *tmp;
	tmp = gmtime(&t);
	ASSERT(tmp != NULL); /* seems that there is no reason (at least in glibc
							docs) localtime will return NULL */

	strftime(buf256,sizeof(buf256),"%a, %d %b %Y %H:%M:%S GMT", tmp);

	return buf256;
}

void http_append_standard_headers ( struct Request *req )
{
	/* we might want to implement these later (perhaps in dump_file etc)
       10.7  Expires ( might have some use for sending )
       10.10 Last-Modified ( might have use for sending )
       10.12 Pragma (might have use for sending)
       10.16 WWW-Authenticate */

	request_enqueue_header_str( req, "Connection: close\r\n" );
	request_enqueue_header_str( req, "Date: " );
	request_enqueue_header_str( req, http_date( time(NULL) ) );
	request_enqueue_header_str( req, "\r\n" );
	request_enqueue_header_str( req, HTTP_SERVER_HEADER );
}

enum result_t http_process_headers ( struct Request *req )
{
	int k;
	const char *c, *line;
	k = req->processed_lines;
	
	while (k < req->num_lines)
	{
		req->processed_lines++;

		/* empty line marks the end of request headers */
		if (req->lines[k][0] == 0) return SUCCESS;

		line = req->lines[k];
		DEBUG("line %d = '%s'", k, line);

		/* find the pointer to the header value: (and a modest sanity check) */
		c = strchr(line, ':');
		if (c == NULL) return FAIL;
		c++;
		if (c[0] != ' ') return FAIL;
		c++; /* now c points to the value of the header */

		if (prefix_icmp(line, "User-Agent: "))
		{
			req->user_agent = c;
			DEBUG("User agent: '%s'", c);
		}
		else if (prefix_icmp(line, "Referer: "))
		{
			if ( http_valid_raw_uri(c) )
				req->referer = c;
			else
				WARN("invalid referer value '%s'", c);
		}
		else if (prefix_icmp(line, "From: "))
		{
			/* useless field... I wouldn't waste a pointer for it */
		}
		else if (prefix_icmp(line, "If-Modified-Since: "))
		{
			/* TODO */
		}
		else if (prefix_icmp(line, "Authorization: "))
		{
			/* TODO */
		}

		/*
		 * TODO: we might want to implement these later: 
		 10.3  Content-Encoding ( after POST )
		 10.4  Content-Length ( after POST )
		 10.5  Content-Type ( after POST )
		 */

		k++;
	}

	return NEED_MORE;
}

/* we assume no null characters in the request (header) text */
/* TODO: add a check for line length so that no DOS attack can result from a
 * super long line! */
/* TODO: Header fields can be extended over multiple lines by preceding each
 * extra line with at least one SP or HT, though this is not recommended.
 * (rfc1945) - in this case we probably need to merge the tokenize and process
 * function... */
void http_tokenize_header_lines( struct Request *req )
{
	char *c;
	char *line_start;

	if (req->done_tokenizing_headers) return;

	line_start = req->last_read;

	for ( c = req->last_read; *c != 0; c++ )
	{
		if ( c[0] == '\r' && c[1] == '\n' ) 
		{
			c[0] = 0;
			c++;
		}

		if ( c[0] == '\n' )
		{
			c[0] = 0;

			/* push the line start pointer to the req->lines[] array */
			array_push( (void ***) & (req->lines), & req->num_lines, & req->lines_siz, line_start );
			req->last_read = line_start = c+1;

			/* empty line marks end of request headers, don't tokenize more */
			if (req->lines[req->num_lines - 1][0] == 0)
			{
				DEBUG("done tokenizing headers");
				/* warning: req_content might be pointed to past the end of
				 * i_buffer, we'll need some nontrivial pointer arithmetic to
				 * check for the end of the request content... */
				req->req_content = line_start; 
				req->done_tokenizing_headers = True;
				break;
			}
		}

	}
}

void http_process( struct Request *req )
{
	enum result_t res;

	/* tokenize the lines in req->i_buffer and the pointers in req->lines[] */
	http_tokenize_header_lines ( req );

	/* First line of the HTTP request */
	res = http_parse_request_line( req );

	switch (res) 
	{
		case SUCCESS:
			DEBUG("successfully parsed request line");
			req->processed_lines = 1;
			break;
		case FAIL:
			DEBUG("http_parse_request_line failed");
			http_boilerplate_response( req, HTTP(400) );
			goto cleanup;
		case NEED_MORE: /* fall thru */
			DEBUG("need more");
		case ALREADY_DONE:
			DEBUG("already done");
			break;
		default:
			DIE(EXIT_BUG, "should not reach here");
			break;
	}


	if ( req->is_simple )
	{
		req->had_enough_input = True;
	}
	else
	{
		if (! req->done_tokenizing_headers ) return;

		res = http_process_headers( req );
		switch ( res )
		{
			case SUCCESS:
				req->had_enough_input = True; /* conditional below */
				break;
			case FAIL:
				http_boilerplate_response( req, HTTP(400) );
				goto cleanup;
			case NEED_MORE:
				/* do nothing, will return immediately below due to not
				 * had_enough_input ... */
				break;
			default:
				DIE(EXIT_BUG, "should not reach here");
				break;
		}
	}

	/* if there's more to be read, then dont continue the processing */
	if (! req->had_enough_input ) return;

	ASSERT(!req->h_done);
	ASSERT(!req->o_done);

	switch(req->method)
	{
		case GET:
			http_execute_get(req);
			break;
		default:
			http_boilerplate_response( req, HTTP(501) );
			break;
	}

cleanup:

	http_append_standard_headers( req );
	request_finalize_header( req );

	/* LOG: */
	/*               date ipaddress rsp meth uri httpver useragent */
	fprintf( stdout, "%s %d.%d.%d.%d %d %s %s HTTP/%d.%d %s\n",
			log_date(time(NULL)),
			IPADDRESS(req->remote_addr.sin_addr.s_addr),
			req->resp_status,
			(req->method != UNKNOWN ? req->lines[0] : "UNKNOWN"),
			(req->request_uri != NULL ? req->request_uri : "%"),
			(req->ver_major >= 0 ? req->ver_major : 0),
			(req->ver_minor >= 0 ? req->ver_minor : 0),
			(req->user_agent == NULL ? "-" : req->user_agent ) );

	fflush( stdout );
}

/* )******** SETOPTS ******* (*/

void set_opts(int argc, char *argv[])
{
	/* No getopt(3) on Windows! gah! */
	char **opt;
	for (opt = argv+1; *opt != NULL; opt++)
	{
		if (*opt[0] == '-') 
		{
			switch( (*opt)[1] )
			{
				case 'Q':
					slib_verbosity = 0;
					break;
				case 'q':
					slib_verbosity = 1;
					break;
				case 'v':
					slib_verbosity = 3;
					break;
				case 'V':
					slib_verbosity = 4;
					break;
				case 'l':
					config_list_directories = False;
					break;
				case 'p':
					opt++;
					ASSERTM(*opt != NULL, "Missing argument to -p");
					config_bind_port = atoi(*opt);
					ASSERTM(config_bind_port > 0, "Invalid port: %s", *opt);
					break;
				case 'r':
					opt++;
					ASSERTM(*opt != NULL, "Missing argument to -r");
					ASSERTM(config_doc_root == NULL, "conflicting values of document root" );
					config_doc_root = (char*) malloc(strlen(*opt)+1);
					strcpy(config_doc_root, *opt);
					break;
				case 'G':
					fprintf(stderr, LEGALNOTICE);
					exit(0);
					break;
				case 'd':
					config_dummy = True;
					break;
				case 'u':
					config_utf8text = True;
					break;
			}
		}
		else
		{
			ASSERTM( config_doc_root == NULL, "conflicting values of document root" );
			config_doc_root = (char*) malloc(strlen(*opt)+1);
			strcpy(config_doc_root, *opt);
		}
	}

	/* sanity check */

	if (config_doc_root != NULL && io_filetype(config_doc_root) != DIRECTORY )
	{
		DIE(EXIT_USER, "Invalid document root: %s", config_doc_root);
	}
}

#ifdef WIN32
void set_signal_handlers( )
{
}
#else
void set_signal_handlers( )
{
	signal( SIGPIPE, SIG_IGN );
}
#endif

void common_system_check() {
	struct file_properties dummy;
	ASSERT(sizeof(dummy.size) == 8); // 64-bit off_t
}

#ifdef WIN32
void os_check()
{
	OSVERSIONINFO ver_info;
	ver_info.dwOSVersionInfoSize = sizeof(ver_info);
	GetVersionEx(&ver_info);

	/* FIXME: how about 64 bit?? */
	if (ver_info.dwPlatformId != VER_PLATFORM_WIN32_NT)
	{
		printf("Platform not supported!\n");
		abort();
	}
}
#else
void os_check()
{
	// POSIX *should* do.
}
#endif

/* )********* MAIN ********* (*/

int main(int argc, char *argv[])
{
	int s;
	// Preliminary checks on OS (win9x/ME not supported)
	os_check();
	common_system_check();

	/* parse arguments */
	set_opts(argc, argv);

	/* initialize global variables */
	memset(requests, 0, sizeof(requests));
	mime_init();  /* This needs to be after set_opts because of -u */
	set_signal_handlers();

	DEBUG("sizeof(struct Request) = %zd", sizeof(struct Request));
	DEBUG("sizeof(struct LinkedBlockItem) = %zd", sizeof(struct LinkedBlockItem));

	if (config_doc_root == NULL && (! config_dummy ) )
	{
		fprintf(stderr, USAGE);
#ifdef WIN32
		system("pause");
#endif
		return 1;
	}

	INFO("onehttpd v%d.%d", ONEHTTPD_VERSION_MAJOR, ONEHTTPD_VERSION_MINOR);

	ASSERTM(wsockinit() == SUCCESS, "Error initializing winsock!");
	INFO("options: PORT=%d, DOCROOT='%s'", config_bind_port, config_doc_root);

	s = server_listen();
	while ( True )
	{
		server_select( s );
	}

	return 0;
}

/* )********* END *********** */

/****************************************************************************

                    GNU GENERAL PUBLIC LICENSE
                       Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The licenses for most software are designed to take away your
freedom to share and change it.  By contrast, the GNU General Public
License is intended to guarantee your freedom to share and change free
software--to make sure the software is free for all its users.  This
General Public License applies to most of the Free Software
Foundation's software and to any other program whose authors commit to
using it.  (Some other Free Software Foundation software is covered by
the GNU Lesser General Public License instead.)  You can apply it to
your programs, too.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
this service if you wish), that you receive source code or can get it
if you want it, that you can change the software or use pieces of it
in new free programs; and that you know you can do these things.

  To protect your rights, we need to make restrictions that forbid
anyone to deny you these rights or to ask you to surrender the rights.
These restrictions translate to certain responsibilities for you if you
distribute copies of the software, or if you modify it.

  For example, if you distribute copies of such a program, whether
gratis or for a fee, you must give the recipients all the rights that
you have.  You must make sure that they, too, receive or can get the
source code.  And you must show them these terms so they know their
rights.

  We protect your rights with two steps: (1) copyright the software, and
(2) offer you this license which gives you legal permission to copy,
distribute and/or modify the software.

  Also, for each author's protection and ours, we want to make certain
that everyone understands that there is no warranty for this free
software.  If the software is modified by someone else and passed on, we
want its recipients to know that what they have is not the original, so
that any problems introduced by others will not reflect on the original
authors' reputations.

  Finally, any free program is threatened constantly by software
patents.  We wish to avoid the danger that redistributors of a free
program will individually obtain patent licenses, in effect making the
program proprietary.  To prevent this, we have made it clear that any
patent must be licensed for everyone's free use or not licensed at all.

  The precise terms and conditions for copying, distribution and
modification follow.

                    GNU GENERAL PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. This License applies to any program or other work which contains
a notice placed by the copyright holder saying it may be distributed
under the terms of this General Public License.  The "Program", below,
refers to any such program or work, and a "work based on the Program"
means either the Program or any derivative work under copyright law:
that is to say, a work containing the Program or a portion of it,
either verbatim or with modifications and/or translated into another
language.  (Hereinafter, translation is included without limitation in
the term "modification".)  Each licensee is addressed as "you".

Activities other than copying, distribution and modification are not
covered by this License; they are outside its scope.  The act of
running the Program is not restricted, and the output from the Program
is covered only if its contents constitute a work based on the
Program (independent of having been made by running the Program).
Whether that is true depends on what the Program does.

  1. You may copy and distribute verbatim copies of the Program's
source code as you receive it, in any medium, provided that you
conspicuously and appropriately publish on each copy an appropriate
copyright notice and disclaimer of warranty; keep intact all the
notices that refer to this License and to the absence of any warranty;
and give any other recipients of the Program a copy of this License
along with the Program.

You may charge a fee for the physical act of transferring a copy, and
you may at your option offer warranty protection in exchange for a fee.

  2. You may modify your copy or copies of the Program or any portion
of it, thus forming a work based on the Program, and copy and
distribute such modifications or work under the terms of Section 1
above, provided that you also meet all of these conditions:

    a) You must cause the modified files to carry prominent notices
    stating that you changed the files and the date of any change.

    b) You must cause any work that you distribute or publish, that in
    whole or in part contains or is derived from the Program or any
    part thereof, to be licensed as a whole at no charge to all third
    parties under the terms of this License.

    c) If the modified program normally reads commands interactively
    when run, you must cause it, when started running for such
    interactive use in the most ordinary way, to print or display an
    announcement including an appropriate copyright notice and a
    notice that there is no warranty (or else, saying that you provide
    a warranty) and that users may redistribute the program under
    these conditions, and telling the user how to view a copy of this
    License.  (Exception: if the Program itself is interactive but
    does not normally print such an announcement, your work based on
    the Program is not required to print an announcement.)

These requirements apply to the modified work as a whole.  If
identifiable sections of that work are not derived from the Program,
and can be reasonably considered independent and separate works in
themselves, then this License, and its terms, do not apply to those
sections when you distribute them as separate works.  But when you
distribute the same sections as part of a whole which is a work based
on the Program, the distribution of the whole must be on the terms of
this License, whose permissions for other licensees extend to the
entire whole, and thus to each and every part regardless of who wrote it.

Thus, it is not the intent of this section to claim rights or contest
your rights to work written entirely by you; rather, the intent is to
exercise the right to control the distribution of derivative or
collective works based on the Program.

In addition, mere aggregation of another work not based on the Program
with the Program (or with a work based on the Program) on a volume of
a storage or distribution medium does not bring the other work under
the scope of this License.

  3. You may copy and distribute the Program (or a work based on it,
under Section 2) in object code or executable form under the terms of
Sections 1 and 2 above provided that you also do one of the following:

    a) Accompany it with the complete corresponding machine-readable
    source code, which must be distributed under the terms of Sections
    1 and 2 above on a medium customarily used for software interchange; or,

    b) Accompany it with a written offer, valid for at least three
    years, to give any third party, for a charge no more than your
    cost of physically performing source distribution, a complete
    machine-readable copy of the corresponding source code, to be
    distributed under the terms of Sections 1 and 2 above on a medium
    customarily used for software interchange; or,

    c) Accompany it with the information you received as to the offer
    to distribute corresponding source code.  (This alternative is
    allowed only for noncommercial distribution and only if you
    received the program in object code or executable form with such
    an offer, in accord with Subsection b above.)

The source code for a work means the preferred form of the work for
making modifications to it.  For an executable work, complete source
code means all the source code for all modules it contains, plus any
associated interface definition files, plus the scripts used to
control compilation and installation of the executable.  However, as a
special exception, the source code distributed need not include
anything that is normally distributed (in either source or binary
form) with the major components (compiler, kernel, and so on) of the
operating system on which the executable runs, unless that component
itself accompanies the executable.

If distribution of executable or object code is made by offering
access to copy from a designated place, then offering equivalent
access to copy the source code from the same place counts as
distribution of the source code, even though third parties are not
compelled to copy the source along with the object code.

  4. You may not copy, modify, sublicense, or distribute the Program
except as expressly provided under this License.  Any attempt
otherwise to copy, modify, sublicense or distribute the Program is
void, and will automatically terminate your rights under this License.
However, parties who have received copies, or rights, from you under
this License will not have their licenses terminated so long as such
parties remain in full compliance.

  5. You are not required to accept this License, since you have not
signed it.  However, nothing else grants you permission to modify or
distribute the Program or its derivative works.  These actions are
prohibited by law if you do not accept this License.  Therefore, by
modifying or distributing the Program (or any work based on the
Program), you indicate your acceptance of this License to do so, and
all its terms and conditions for copying, distributing or modifying
the Program or works based on it.

  6. Each time you redistribute the Program (or any work based on the
Program), the recipient automatically receives a license from the
original licensor to copy, distribute or modify the Program subject to
these terms and conditions.  You may not impose any further
restrictions on the recipients' exercise of the rights granted herein.
You are not responsible for enforcing compliance by third parties to
this License.

  7. If, as a consequence of a court judgment or allegation of patent
infringement or for any other reason (not limited to patent issues),
conditions are imposed on you (whether by court order, agreement or
otherwise) that contradict the conditions of this License, they do not
excuse you from the conditions of this License.  If you cannot
distribute so as to satisfy simultaneously your obligations under this
License and any other pertinent obligations, then as a consequence you
may not distribute the Program at all.  For example, if a patent
license would not permit royalty-free redistribution of the Program by
all those who receive copies directly or indirectly through you, then
the only way you could satisfy both it and this License would be to
refrain entirely from distribution of the Program.

If any portion of this section is held invalid or unenforceable under
any particular circumstance, the balance of the section is intended to
apply and the section as a whole is intended to apply in other
circumstances.

It is not the purpose of this section to induce you to infringe any
patents or other property right claims or to contest validity of any
such claims; this section has the sole purpose of protecting the
integrity of the free software distribution system, which is
implemented by public license practices.  Many people have made
generous contributions to the wide range of software distributed
through that system in reliance on consistent application of that
system; it is up to the author/donor to decide if he or she is willing
to distribute software through any other system and a licensee cannot
impose that choice.

This section is intended to make thoroughly clear what is believed to
be a consequence of the rest of this License.

  8. If the distribution and/or use of the Program is restricted in
certain countries either by patents or by copyrighted interfaces, the
original copyright holder who places the Program under this License
may add an explicit geographical distribution limitation excluding
those countries, so that distribution is permitted only in or among
countries not thus excluded.  In such case, this License incorporates
the limitation as if written in the body of this License.

  9. The Free Software Foundation may publish revised and/or new versions
of the General Public License from time to time.  Such new versions will
be similar in spirit to the present version, but may differ in detail to
address new problems or concerns.

Each version is given a distinguishing version number.  If the Program
specifies a version number of this License which applies to it and "any
later version", you have the option of following the terms and conditions
either of that version or of any later version published by the Free
Software Foundation.  If the Program does not specify a version number of
this License, you may choose any version ever published by the Free Software
Foundation.

  10. If you wish to incorporate parts of the Program into other free
programs whose distribution conditions are different, write to the author
to ask for permission.  For software which is copyrighted by the Free
Software Foundation, write to the Free Software Foundation; we sometimes
make exceptions for this.  Our decision will be guided by the two goals
of preserving the free status of all derivatives of our free software and
of promoting the sharing and reuse of software generally.

                            NO WARRANTY

  11. BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
REPAIR OR CORRECTION.

  12. IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
POSSIBILITY OF SUCH DAMAGES.

                     END OF TERMS AND CONDITIONS

            How to Apply These Terms to Your New Programs

  If you develop a new program, and you want it to be of the greatest
possible use to the public, the best way to achieve this is to make it
free software which everyone can redistribute and change under these terms.

  To do so, attach the following notices to the program.  It is safest
to attach them to the start of each source file to most effectively
convey the exclusion of warranty; and each file should have at least
the "copyright" line and a pointer to where the full notice is found.

    <one line to give the program's name and a brief idea of what it does.>
    Copyright (C) <year>  <name of author>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

Also add information on how to contact you by electronic and paper mail.

If the program is interactive, make it output a short notice like this
when it starts in an interactive mode:

    Gnomovision version 69, Copyright (C) year name of author
    Gnomovision comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
    This is free software, and you are welcome to redistribute it
    under certain conditions; type `show c' for details.

The hypothetical commands `show w' and `show c' should show the appropriate
parts of the General Public License.  Of course, the commands you use may
be called something other than `show w' and `show c'; they could even be
mouse-clicks or menu items--whatever suits your program.

You should also get your employer (if you work as a programmer) or your
school, if any, to sign a "copyright disclaimer" for the program, if
necessary.  Here is a sample; alter the names:

  Yoyodyne, Inc., hereby disclaims all copyright interest in the program
  `Gnomovision' (which makes passes at compilers) written by James Hacker.

  <signature of Ty Coon>, 1 April 1989
  Ty Coon, President of Vice

This General Public License does not permit incorporating your program into
proprietary programs.  If your program is a subroutine library, you may
consider it more useful to permit linking proprietary applications with the
library.  If this is what you want to do, use the GNU Lesser General
Public License instead of this License.

****************************************************************************/
#else /* IS_RESOURCE_FILE */

#include <windows.h>

1 VERSIONINFO
FILEVERSION ONEHTTPD_VERSION_MAJOR,ONEHTTPD_VERSION_MINOR,0,0
PRODUCTVERSION ONEHTTPD_VERSION_MAJOR,ONEHTTPD_VERSION_MINOR,0,0
FILETYPE VFT_APP
{
	BLOCK "StringFileInfo"
	{
		BLOCK "040904E4"
		{
			VALUE "CompanyName", "Element14.org"
			VALUE "FileVersion", ONEHTTPD_VERSION_STRING
			VALUE "FileDescription", "The One HTTP Server"
			VALUE "InternalName", "onehttpd.exe"
			VALUE "LegalCopyright", "Copyright (C) 2008-2010 Sidney Fong (GPLv2)"
			VALUE "OriginalFilename", "onehttpd.exe"
			VALUE "ProductName", "OneHTTPD Web Server"
			VALUE "ProductVersion", ""
		}
	}
	BLOCK "VarFileInfo"
	{
		VALUE "Translation", 0x0409, 1252
	}
}

100 ICON "onehttpd.ico"

#endif
/*
endef
# */
