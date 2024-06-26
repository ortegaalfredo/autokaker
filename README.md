# autokaker
Automated vulnerability discovery and refactor (autopatcher)

## Install

Execute:

```
pip install -r requirements.txt
```

## API Requirements

Autokaker and Autopatcher can use two different LLM APIs:

. Neuroengine free API using LLama3 and other open models
. OpenAI API

To use the OpenAI api, the api key must be in the file api-key.txt

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

Patching zlib project:

```
python autok.py --patch ./zlib
```

Patching zlib project and testing the patch using 'make':

```
python autok.py --patch ./zlib --make "make"
```



