# **PyDump**
<div align="center">
<image src="https://cdn.discordapp.com/attachments/843628315146321940/1006717343042379846/pydump.gif">
</div>
<p align="center">
    <em>PyDump, cross-platform solution for Memory Dumps</em></p>
  <p align="center">
    <a href="https://github.com/ZaikoARG/PyDump/blob/main/LICENSE">
      <img src="https://img.shields.io/badge/license-Apache%202-blue.svg" />
    </a>
    <a href="https://www.python.org/">
    	<img src="https://img.shields.io/badge/built%20with-Python%203-red.svg" />
    </a>
    <a href="">
    	<img src="https://img.shields.io/badge/platform-Win%2032%20%7C%20Win%2064%20%7C%20Linux%2032%20%7C%20Linux%2064-blue.svg" />
    </a>
  </p>
</p>

---

**Discord:** ZaikoARG#1187

---

PyDump is a cross-platform command line tool written entirely in Python for creating memory dumps of a specific process.

Many times to create memory dumps we must install a different tool for Windows than for Linux, or we do not find a quick and easy solution to make a memory dump in our Operating System.
PyDump offers the ability to create memory dumps with a simple command line and cross-platform support, so you don't have to worry about how certain things are done on your OS.

PyDump currently supports the following operating systems:

*  **Windows**
*  **Linux**

--- 

## Example of Usage

Dump full memory of a chrome.exe process

`python pydump.py -n chrome.exe -o dump.bin -fd`

Dump a reduced part of the memory of the chrome.exe process

`python pydump.py -n chrome.exe -o dump.bin -md` 

Dump full memory knowing the Process ID

`python pydump.py -p 1234 -o dump.bin -fd`

## Documentation
`python pydump.py -p {pid} -o {filename} (options)`
|Option|Description|
|--|--|
|-p, --pid [process_id]|Specify the Process ID to dump memory.|
|-n, --process-name [process_name]|Specify the Process Name to dump memory.|
|-o, --output [file]|Output file name where the dump will be saved.|
|-md|Create a Mini Dump of the process. Includes only the memory regions of type PRIVATE on Windows and only READABLE on Linux.|
|-fd|Create a Full Dump of the process. Includes any type of memory: PRIVATE, IMAGE and MAPPED on Windows and PRIVATE and SHARED on Linux.|

## License
Copyright © 2022, ZaikoARG. All rights reserved.

Licensed under the Apache 2.0 License.
