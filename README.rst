x86-64-pe-emu
=============

        .. image:: http://i.imgur.com/IRFe6Zd.png

        This is a simple x86-64 emulator for AMD64 PE files (Windows binaries).  This was
        originally designed to run device drivers for analysis, but it will be extended to
        be much more.

Notes
-----

        1. This was mainly done for analysis of Windows kernel device drivers (packed ones mostly.)
        2. This is very experiemental, and it relies heavily on the underlying libraries.
        3. Some stuff are ultimately broken.
        4. It can run under any system that unicorn/capstone engines support (Linux, Windows, Mac OS, etc.)

Requirements
------------

        - Unicorn engine
        - Capstone engine
        - pefile
        - numpy
        - Python 2.7
        - Curses (_curses module)

This looks silly, why?
----------------------

        Personal reasons, fun experience, etc.  This can greatly aid somehow in reverse
        engineering tasks.

        This will definitely be extended to be much more, but for now, it's just a silly
        PE runner, it "fake-resolves" imports as dummy functions.
        As noted before, this was originally written for device driver analysis, so not
        much stuff is done, it's kept minimal (for now).

Disclaimer
----------

        Don't look at this yet, this is pretty much in an alpha stage, and will most
        likely take time to improve.

