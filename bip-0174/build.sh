#!/bin/bash

pdflatex -output-format=pdf coinjoin-workflow.tex && \
inkscape --with-gui --export-text-to-path \
  --export-plain-svg=coinjoin-workflow.svg coinjoin-workflow.pdf && \
pdflatex -output-format=pdf multisig-workflow.tex && \
inkscape --with-gui --export-text-to-path \
  --export-plain-svg=multisig-workflow.svg multisig-workflow.pdf && \
echo '"success"'
