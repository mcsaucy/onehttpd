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

#define UTF_8_SUPPORT //undef this if you don't want it...

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

#ifdef UTF_8_SUPPORT
#define UTF_USE \
"  -u       Use 'charset=utf-8' in Content-Type for text files and listings.\n"\

#endif

#ifdef UNIX_ENOUGH
#define USAGE UTF_USE USAGE_BASE \
"                                                                           \n"\
"Example: onehttpd -p 8008 /var/www   # Serve files in /var/www on port 8008\n\n"
#else
#define USAGE UTF_USE USAGE_BASE \
"                                                                           \n"\
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
/*  cat /etc/mime.types |  perl -ne 'next if not /\t+/; chomp; ($a, $b) = split(/\t+/); @exts = split(/\s/, $b); foreach (@exts) { print "$_\",\"$a\",\""; } ' */
/* Just be sure to have the last element of the array be NULL */
const char * mime_dataraw[] = 
{"ez","application/andrew-inset","anx","application/annodex","atom","application/atom+xml","atomcat","application/atomcat+xml","atomsrv","application/atomserv+xml","lin","application/bbolin","cap","application/cap","pcap","application/cap","cu","application/cu-seeme","davmount","application/davmount+xml","tsp","application/dsptype","es","application/ecmascript","spl","application/futuresplash","hta","application/hta","jar","application/java-archive","ser","application/java-serialized-object","class","application/java-vm","js","application/javascript","m4g","application/m3g","hqx","application/mac-binhex40","cpt","application/mac-compactpro","nb","application/mathematica","nbp","application/mathematica","mdb","application/msaccess","doc","application/msword","dot","application/msword","mxf","application/mxf","bin","application/octet-stream","oda","application/oda","ogx","application/ogg","pdf","application/pdf","key","application/pgp-keys","pgp","application/pgp-signature","prf","application/pics-rules","ps","application/postscript","ai","application/postscript","eps","application/postscript","epsi","application/postscript","epsf","application/postscript","eps2","application/postscript","eps3","application/postscript","rar","application/rar","rdf","application/rdf+xml","rss","application/rss+xml","rtf","application/rtf","smi","application/smil","smil","application/smil","xhtml","application/xhtml+xml","xht","application/xhtml+xml","xml","application/xml","xsl","application/xml","xsd","application/xml","xspf","application/xspf+xml","zip","application/zip","apk","application/vnd.android.package-archive","cdy","application/vnd.cinderella","kml","application/vnd.google-earth.kml+xml","kmz","application/vnd.google-earth.kmz","xul","application/vnd.mozilla.xul+xml","xls","application/vnd.ms-excel","xlb","application/vnd.ms-excel","xlt","application/vnd.ms-excel","cat","application/vnd.ms-pki.seccat","stl","application/vnd.ms-pki.stl","ppt","application/vnd.ms-powerpoint","pps","application/vnd.ms-powerpoint","odc","application/vnd.oasis.opendocument.chart","odb","application/vnd.oasis.opendocument.database","odf","application/vnd.oasis.opendocument.formula","odg","application/vnd.oasis.opendocument.graphics","otg","application/vnd.oasis.opendocument.graphics-template","odi","application/vnd.oasis.opendocument.image","odp","application/vnd.oasis.opendocument.presentation","otp","application/vnd.oasis.opendocument.presentation-template","ods","application/vnd.oasis.opendocument.spreadsheet","ots","application/vnd.oasis.opendocument.spreadsheet-template","odt","application/vnd.oasis.opendocument.text","odm","application/vnd.oasis.opendocument.text-master","ott","application/vnd.oasis.opendocument.text-template","oth","application/vnd.oasis.opendocument.text-web","xlsx","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet","xltx","application/vnd.openxmlformats-officedocument.spreadsheetml.template","pptx","application/vnd.openxmlformats-officedocument.presentationml.presentation","ppsx","application/vnd.openxmlformats-officedocument.presentationml.slideshow","potx","application/vnd.openxmlformats-officedocument.presentationml.template","docx","application/vnd.openxmlformats-officedocument.wordprocessingml.document","dotx","application/vnd.openxmlformats-officedocument.wordprocessingml.template","cod","application/vnd.rim.cod","mmf","application/vnd.smaf","sdc","application/vnd.stardivision.calc","sds","application/vnd.stardivision.chart","sda","application/vnd.stardivision.draw","sdd","application/vnd.stardivision.impress","sdf","application/vnd.stardivision.math","sdw","application/vnd.stardivision.writer","sgl","application/vnd.stardivision.writer-global","sxc","application/vnd.sun.xml.calc","stc","application/vnd.sun.xml.calc.template","sxd","application/vnd.sun.xml.draw","std","application/vnd.sun.xml.draw.template","sxi","application/vnd.sun.xml.impress","sti","application/vnd.sun.xml.impress.template","sxm","application/vnd.sun.xml.math","sxw","application/vnd.sun.xml.writer","sxg","application/vnd.sun.xml.writer.global","stw","application/vnd.sun.xml.writer.template","sis","application/vnd.symbian.install","vsd","application/vnd.visio","wbxml","application/vnd.wap.wbxml","wmlc","application/vnd.wap.wmlc","wmlsc","application/vnd.wap.wmlscriptc","wpd","application/vnd.wordperfect","wp5","application/vnd.wordperfect5.1","wk","application/x-123","7z","application/x-7z-compressed","abw","application/x-abiword","dmg","application/x-apple-diskimage","bcpio","application/x-bcpio","torrent","application/x-bittorrent","cab","application/x-cab","cbr","application/x-cbr","cbz","application/x-cbz","cdf","application/x-cdf","cda","application/x-cdf","vcd","application/x-cdlink","pgn","application/x-chess-pgn","cpio","application/x-cpio","csh","application/x-csh","deb","application/x-debian-package","udeb","application/x-debian-package","dcr","application/x-director","dir","application/x-director","dxr","application/x-director","dms","application/x-dms","wad","application/x-doom","dvi","application/x-dvi","rhtml","application/x-httpd-eruby","pfa","application/x-font","pfb","application/x-font","gsf","application/x-font","pcf","application/x-font","pcf.Z","application/x-font","mm","application/x-freemind","spl","application/x-futuresplash","gnumeric","application/x-gnumeric","sgf","application/x-go-sgf","gcf","application/x-graphing-calculator","gtar","application/x-gtar","tgz","application/x-gtar","taz","application/x-gtar","hdf","application/x-hdf","phtml","application/x-httpd-php","pht","application/x-httpd-php","php","application/x-httpd-php","phps","application/x-httpd-php-source","php3","application/x-httpd-php3","php3p","application/x-httpd-php3-preprocessed","php4","application/x-httpd-php4","php5","application/x-httpd-php5","ica","application/x-ica","info","application/x-info","ins","application/x-internet-signup","isp","application/x-internet-signup","iii","application/x-iphone","iso","application/x-iso9660-image","jam","application/x-jam","jnlp","application/x-java-jnlp-file","jmz","application/x-jmol","chrt","application/x-kchart","kil","application/x-killustrator","skp","application/x-koan","skd","application/x-koan","skt","application/x-koan","skm","application/x-koan","kpr","application/x-kpresenter","kpt","application/x-kpresenter","ksp","application/x-kspread","kwd","application/x-kword","kwt","application/x-kword","latex","application/x-latex","lha","application/x-lha","lyx","application/x-lyx","lzh","application/x-lzh","lzx","application/x-lzx","frm","application/x-maker","maker","application/x-maker","frame","application/x-maker","fm","application/x-maker","fb","application/x-maker","book","application/x-maker","fbdoc","application/x-maker","mif","application/x-mif","wmd","application/x-ms-wmd","wmz","application/x-ms-wmz","com","application/x-msdos-program","exe","application/x-msdos-program","bat","application/x-msdos-program","dll","application/x-msdos-program","msi","application/x-msi","nc","application/x-netcdf","pac","application/x-ns-proxy-autoconfig","dat","application/x-ns-proxy-autoconfig","nwc","application/x-nwc","o","application/x-object","oza","application/x-oz-application","p7r","application/x-pkcs7-certreqresp","crl","application/x-pkcs7-crl","pyc","application/x-python-code","pyo","application/x-python-code","qgs","application/x-qgis","shp","application/x-qgis","shx","application/x-qgis","qtl","application/x-quicktimeplayer","rpm","application/x-redhat-package-manager","rb","application/x-ruby","sh","application/x-sh","shar","application/x-shar","swf","application/x-shockwave-flash","swfl","application/x-shockwave-flash","scr","application/x-silverlight","sit","application/x-stuffit","sitx","application/x-stuffit","sv4cpio","application/x-sv4cpio","sv4crc","application/x-sv4crc","tar","application/x-tar","tcl","application/x-tcl","gf","application/x-tex-gf","pk","application/x-tex-pk","texinfo","application/x-texinfo","texi","application/x-texinfo","~","application/x-trash","%","application/x-trash","bak","application/x-trash","old","application/x-trash","sik","application/x-trash","t","application/x-troff","tr","application/x-troff","roff","application/x-troff","man","application/x-troff-man","me","application/x-troff-me","ms","application/x-troff-ms","ustar","application/x-ustar","src","application/x-wais-source","wz","application/x-wingz","crt","application/x-x509-ca-cert","xcf","application/x-xcf","fig","application/x-xfig","xpi","application/x-xpinstall","amr","audio/amr","awb","audio/amr-wb","amr","audio/amr","awb","audio/amr-wb","axa","audio/annodex","au","audio/basic","snd","audio/basic","flac","audio/flac","mid","audio/midi","midi","audio/midi","kar","audio/midi","mpga","audio/mpeg","mpega","audio/mpeg","mp2","audio/mpeg","mp3","audio/mpeg","m4a","audio/mpeg","m3u","audio/mpegurl","oga","audio/ogg","ogg","audio/ogg","spx","audio/ogg","sid","audio/prs.sid","aif","audio/x-aiff","aiff","audio/x-aiff","aifc","audio/x-aiff","gsm","audio/x-gsm","m3u","audio/x-mpegurl","wma","audio/x-ms-wma","wax","audio/x-ms-wax","ra","audio/x-pn-realaudio","rm","audio/x-pn-realaudio","ram","audio/x-pn-realaudio","ra","audio/x-realaudio","pls","audio/x-scpls","sd2","audio/x-sd2","wav","audio/x-wav","alc","chemical/x-alchemy","cac","chemical/x-cache","cache","chemical/x-cache","csf","chemical/x-cache-csf","cbin","chemical/x-cactvs-binary","cascii","chemical/x-cactvs-binary","ctab","chemical/x-cactvs-binary","cdx","chemical/x-cdx","cer","chemical/x-cerius","c3d","chemical/x-chem3d","chm","chemical/x-chemdraw","cif","chemical/x-cif","cmdf","chemical/x-cmdf","cml","chemical/x-cml","cpa","chemical/x-compass","bsd","chemical/x-crossfire","csml","chemical/x-csml","csm","chemical/x-csml","ctx","chemical/x-ctx","cxf","chemical/x-cxf","cef","chemical/x-cxf","smi","#chemical/x-daylight-smiles","emb","chemical/x-embl-dl-nucleotide","embl","chemical/x-embl-dl-nucleotide","spc","chemical/x-galactic-spc","inp","chemical/x-gamess-input","gam","chemical/x-gamess-input","gamin","chemical/x-gamess-input","fch","chemical/x-gaussian-checkpoint","fchk","chemical/x-gaussian-checkpoint","cub","chemical/x-gaussian-cube","gau","chemical/x-gaussian-input","gjc","chemical/x-gaussian-input","gjf","chemical/x-gaussian-input","gal","chemical/x-gaussian-log","gcg","chemical/x-gcg8-sequence","gen","chemical/x-genbank","hin","chemical/x-hin","istr","chemical/x-isostar","ist","chemical/x-isostar","jdx","chemical/x-jcamp-dx","dx","chemical/x-jcamp-dx","kin","chemical/x-kinemage","mcm","chemical/x-macmolecule","mmd","chemical/x-macromodel-input","mmod","chemical/x-macromodel-input","mol","chemical/x-mdl-molfile","rd","chemical/x-mdl-rdfile","rxn","chemical/x-mdl-rxnfile","sd","chemical/x-mdl-sdfile","sdf","chemical/x-mdl-sdfile","tgf","chemical/x-mdl-tgf","mif","#chemical/x-mif","mcif","chemical/x-mmcif","mol2","chemical/x-mol2","b","chemical/x-molconn-Z","gpt","chemical/x-mopac-graph","mop","chemical/x-mopac-input","mopcrt","chemical/x-mopac-input","mpc","chemical/x-mopac-input","zmt","chemical/x-mopac-input","moo","chemical/x-mopac-out","mvb","chemical/x-mopac-vib","asn","chemical/x-ncbi-asn1","prt","chemical/x-ncbi-asn1-ascii","ent","chemical/x-ncbi-asn1-ascii","val","chemical/x-ncbi-asn1-binary","aso","chemical/x-ncbi-asn1-binary","asn","chemical/x-ncbi-asn1-spec","pdb","chemical/x-pdb","ent","chemical/x-pdb","ros","chemical/x-rosdal","sw","chemical/x-swissprot","vms","chemical/x-vamas-iso14976","vmd","chemical/x-vmd","xtel","chemical/x-xtel","xyz","chemical/x-xyz","gif","image/gif","ief","image/ief","jpeg","image/jpeg","jpg","image/jpeg","jpe","image/jpeg","pcx","image/pcx","png","image/png","svg","image/svg+xml","svgz","image/svg+xml","tiff","image/tiff","tif","image/tiff","djvu","image/vnd.djvu","djv","image/vnd.djvu","wbmp","image/vnd.wap.wbmp","cr2","image/x-canon-cr2","crw","image/x-canon-crw","ras","image/x-cmu-raster","cdr","image/x-coreldraw","pat","image/x-coreldrawpattern","cdt","image/x-coreldrawtemplate","cpt","image/x-corelphotopaint","erf","image/x-epson-erf","ico","image/x-icon","art","image/x-jg","jng","image/x-jng","bmp","image/x-ms-bmp","nef","image/x-nikon-nef","orf","image/x-olympus-orf","psd","image/x-photoshop","pnm","image/x-portable-anymap","pbm","image/x-portable-bitmap","pgm","image/x-portable-graymap","ppm","image/x-portable-pixmap","rgb","image/x-rgb","xbm","image/x-xbitmap","xpm","image/x-xpixmap","xwd","image/x-xwindowdump","eml","message/rfc822","igs","model/iges","iges","model/iges","msh","model/mesh","mesh","model/mesh","silo","model/mesh","wrl","model/vrml","vrml","model/vrml","x3dv","model/x3d+vrml","x3d","model/x3d+xml","x3db","model/x3d+binary","manifest","text/cache-manifest","ics","text/calendar","icz","text/calendar","css","text/css","csv","text/csv","323","text/h323","html","text/html","htm","text/html","shtml","text/html","uls","text/iuls","mml","text/mathml","asc","text/plain","txt","text/plain","text","text/plain","pot","text/plain","brf","text/plain","rtx","text/richtext","sct","text/scriptlet","wsc","text/scriptlet","tm","text/texmacs","ts","text/texmacs","tsv","text/tab-separated-values","jad","text/vnd.sun.j2me.app-descriptor","wml","text/vnd.wap.wml","wmls","text/vnd.wap.wmlscript","bib","text/x-bibtex","boo","text/x-boo","h++","text/x-c++hdr","hpp","text/x-c++hdr","hxx","text/x-c++hdr","hh","text/x-c++hdr","c++","text/x-c++src","cpp","text/x-c++src","cxx","text/x-c++src","cc","text/x-c++src","h","text/x-chdr","htc","text/x-component","csh","text/x-csh","c","text/x-csrc","d","text/x-dsrc","diff","text/x-diff","patch","text/x-diff","hs","text/x-haskell","java","text/x-java","lhs","text/x-literate-haskell","moc","text/x-moc","p","text/x-pascal","pas","text/x-pascal","gcd","text/x-pcs-gcd","pl","text/x-perl","pm","text/x-perl","py","text/x-python","scala","text/x-scala","etx","text/x-setext","sh","text/x-sh","tcl","text/x-tcl","tk","text/x-tcl","tex","text/x-tex","ltx","text/x-tex","sty","text/x-tex","cls","text/x-tex","vcs","text/x-vcalendar","vcf","text/x-vcard","3gp","video/3gpp","axv","video/annodex","dl","video/dl","dif","video/dv","dv","video/dv","fli","video/fli","gl","video/gl","mpeg","video/mpeg","mpg","video/mpeg","mpe","video/mpeg","mp4","video/mp4","qt","video/quicktime","mov","video/quicktime","ogv","video/ogg","mxu","video/vnd.mpegurl","flv","video/x-flv","lsf","video/x-la-asf","lsx","video/x-la-asf","mng","video/x-mng","asf","video/x-ms-asf","asx","video/x-ms-asf","wm","video/x-ms-wm","wmv","video/x-ms-wmv","wmx","video/x-ms-wmx","wvx","video/x-ms-wvx","avi","video/x-msvideo","movie","video/x-sgi-movie","mpv","video/x-matroska","mkv","video/x-matroska","ice","x-conference/x-cooltalk","sisx","x-epoc/x-sisx-app","vrm","x-world/x-vrml","vrml","x-world/x-vrml","wrl","x-world/x-vrml",NULL};

/* index of requests[] is the file descriptor */
struct Request *requests[MAX_FILE_DESCRIPTORS];

#ifdef UTF_8_SUPPORT
char config_utf8text = False;
#endif

char config_dummy = False;
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
	const char **c;
	mime_num = 0;
	c = mime_dataraw;

    /* check for end of array and prevent corrupted MIME data array */
	while ( *c != NULL && *(c+1) != NULL ) 
	{
		mime_ext[mime_num] = *c++;
		mime_value[mime_num] = *c++;

#ifdef UTF_8_SUPPORT
		if (config_utf8text == True && strncmp(mime_value[mime_num], "text/", 5) == 0) {
			static const char *charset_utf8 = ";charset=utf-8";
			/* Note: leaky singletons */
			char *mime_with_utf8 = malloc(strlen(mime_value[mime_num]) + strlen(charset_utf8) + 1);
			strcpy(mime_with_utf8, mime_value[mime_num]);
			strcat(mime_with_utf8, charset_utf8);
			mime_value[mime_num] = mime_with_utf8;
		}
#endif

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
#ifdef UTF_8_SUPPORT
				case 'u':
					config_utf8text = True;
					break;
#endif
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
