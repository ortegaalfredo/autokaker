# autokaker
Automated vulnerability discovery and refactor (autopatcher)

```
  _____
 /     \  AI
|  o o  | ___
| \___/ |/   \
|__   __|     |
   | | | 01001|
 __|_|_|_____/
|           |
|  HACK.exe |
|___________|
```

## Install

Execute:

```
pip install -r requirements.txt
```

## API Requirements

Autokaker and Autopatcher can use two different LLM APIs:

1. Neuroengine.ai free API using LLama3 and other open models
2. OpenAI API

To use the OpenAI api, the api key must be in the file api-key.txt, and select the OpenAI model name from the combo box.

The Neuroengine API do not need any key.

#3 Usage

```
autok.py [-h] [--patch] [--make MAKE] path

```

## Auto vuln-discovery example

Analize a single source file:

```
python autok.py source.c
```

## Auto patching an existing project

Patching an example 'zlib' project at directory './zlib':

```
python autok.py --patch ./zlib
```

Patching an example 'zlib' project and testing the patch using 'make':

```
cd zlib
python ../autok.py --patch . --make "make"
```

Patching an example 'zlib' project, testing executing 'make' and compression/decompression test 'example64':

```
cd zlib
python ../autok.py --patch . --make "make&&./example64"
```
