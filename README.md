# How to run the container

## Build and run the container

Since the image copies the source directories, if you modify the `src/` file, please build.

```
docker compose up --build
```

Docker compose lets us run the container with the correct mounts :)

# template

This folder is a possible example submission.

As a student **you can change any file in this directory except for run_fuzzer.sh**.

We will be providing the `run_fuzzer.sh` file.

You must supply a folder with at least a DockerFile that describes how to build/compile/run your fuzzer.

See the assignment spec for more details.

# Notes

This branch uses python 3.14 with Cython

## Google doc notes

<https://docs.google.com/document/d/1kjka3ijjtv6MdvxuVZKznp9sHsXN9ch6YZrAvmUkMf8/edit?tab=t.0>


# welcome to the src code of our fuzzer :)


we will use ultraviolet as the build/venv manager for the python code

## Please install uv
on linux and mac: `curl -LsSf https://astral.sh/uv/install.sh | sh`

## UV explained
uv manages dependecies (fast) to add a depency with uv
`uv add <dependency>==v0.` 
- [more info (the documentation)](https://docs.astral.sh/uv/guides/projects/)

### to run an application 
`uv run main.py` will run main.py, resolving dependencies as needed
I've added a shebang line to do this automatically so if u like you can just run `./main.py`

### what are all these files ?!
metadata is stored in pyproject.toml, like better requirements.txt file, similarly the uv.lock file contains an exact version enumeration of all dependencies. You shouldn't need to directly modify these files.

## P.s.
the source files are placeholders for now, feel free to modify the files

