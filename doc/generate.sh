#!/bin/bash

# install 'pandoc' from pandoc.org on Ubuntu Xenial as follows:
#
#   $ curl -LO https://github.com/jgm/pandoc/releases/download/2.6/pandoc-2.6-1-amd64.deb
#   $ sudo dpkg -i pandoc-2.6-1-amd64.deb
#   $ sudo apt install -y texlive-xetex texlive-fonts-extra

# the distribution docs were built on pandoc 2.6

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# generate PDF
pandoc -f markdown+smart -H "${DIR}/listings-setup.tex" --listings \
    -o "${DIR}/tortuga-kit-awsadapter.pdf" \
    --pdf-engine xelatex \
    --variable geometry:margin=0.5in \
    "${DIR}/tortuga-kit-awsadapter.md"
