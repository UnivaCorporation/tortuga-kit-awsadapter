# tortuga-kit-awsadapter

## Overview

This repository contains the requisite files to build a resource adapter kit
to enable support for Amazon Web Services (AWS) in [Tortuga][].

## Building the kit

Change to subdirectory containing cloned Git repository and run `build-kit`.
`build-kit` is provided by the `tortuga-core` package in the [Tortuga][] source.
Be sure you have activated the tortuga virtual environment as suggested in the [Tortuga build instructions](https://github.com/UnivaCorporation/tortuga#build-instructions) before executing `build-kit`.

## Installation

Install the kit:

```shell
install-kit kit-awsadapter*.tar.bz2
```

See the [Tortuga Installation and Administration Guide](https://github.com/UnivaCorporation/tortuga/blob/master/doc/tortuga-6-admin-guide.md) for configuration
details.

[Tortuga]: https://github.com/UnivaCorporation/tortuga "Tortuga"
