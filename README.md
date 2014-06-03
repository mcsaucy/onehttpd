# Background #
This project was originally taken from https://code.google.com/p/onehttpd/

An attempt is being made to correct issues with this program to make it an incredibly lightweight solution tailored while retaining robustness.

# Introduction #
OneHTTPD is a minimalist web server that is written in one self-contained source file. The primary motivation of the project is to write a small, portable executable to serve static files on a Windows desktop. It currently supports a (small) subset of HTTP/1.0.

# Supported Platforms #
It is tested on Linux (Debian) and Windows (XP). It should work on most Linux systems and Windows 2k+. It might work on some other Unices.

# Building OneHTTPD #
Note that the preferred build environment for Windows executables is the MinGW (cross) compiler under Linux.

The code compiles under gcc and MinGW.

The source file, onehttpd.c, is actually a polyglot. It also serves as the Makefile, and the resource file. Therefore, to make, do the following:
`
$ ln -s onehttpd.c Makefile
$ ln -s onehttpd.c onehttpd.rc
$ make
`
If you wish to build OneHTTPD on Windows, take look at the Makefile part of the source and adopt it to your build environment. Note that it is strongly recommended that you use MinGW, Microsoft's compilers most likely won't work without significant amount of mangling with the source and project settings.

# Documentation #
Any other documentation (besides this page) should be in the source. The first few pages of the source should give you an idea.

# Reporting Bugs #
Please report any bugs in the Issues page.

# Security #
I am surprised that there are people who actually report security vulnerabilities for onehttpd. (I mean, nobody really uses this thing, right?) I am aware of two, so far. Anyway, the known issues are tracked on the tracker tool here, and I generally do fix them. If you are aware of outstanding issues that are not tracked in the issue tracker, please file a new issue.
