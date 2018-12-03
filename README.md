# First-radare2-plugin
This is a radare2 plugin that ads a cmd that integrates with FIRST (Function Identification and Recovery Signature Tool) server.

Please look below to find links to the various FIRST components.
- FIRST server (https://github.com/vrtadmin/FIRST-server): The source code for the FIRST server component. Documentaiton can be found in the repo or at http://first-server.readthedocs.io
- FIRST Integration - IDA Pro (https://github.com/vrtadmin/FIRST-plugin-ida): The source code for the FIRST IDA Pro integration. Documentation can be found in the repo or at http://first-plugin-ida.readthedocs.io

## Installation
- Modify first.config to set the host and your FIRST token (by default it is set to connect to FIRST online server).
- Execute `make`

## Prerequisite
- radare2
- curl

## Usage
	Usage: Fst[?asug]  FIRST plugin
	| Fst               test connection to server
	| Fst?              show this help
	| Fsta [func]       add function to FIRST
	| Fstaa             add all functions to FIRST
	| Fstaac [comment]  add all functions to FIRST with a comment
	| Fstd [addr]       delete annotation from FIRST
	| Fstdd [id]        delete annotation from FIRST of a function that don't exist in this file (you can see all created annotations using Fstgc)
	| Fstg              get annotations saved in FIRST
	| Fstgc             get all created annotations saved in FIRST (this does not depend on the opened file)
	| Fsth [addr]       get annotation history of a function
	| Fsthh [id]    	get annotation history of a function that don't exist in this file (you can see all created annotations using Fstgc)
	| Fst+ [id]         apply annotations
	| Fsts [func]       scan for similar functions in FIRST
	| Fstsa             scan all functions for similar functions in FIRST
