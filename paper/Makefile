# Build the paper PDF.
#
# Requires: pdflatex (TeX Live full or MiKTeX). On Windows install
# MiKTeX from https://miktex.org/. On Linux: `apt install texlive-full`.

PAPER = main

.PHONY: all clean view watch

all: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex
	pdflatex -interaction=nonstopmode $(PAPER).tex
	pdflatex -interaction=nonstopmode $(PAPER).tex   # 2nd pass for refs

clean:
	rm -f *.aux *.log *.out *.toc *.bbl *.blg *.synctex.gz

view: $(PAPER).pdf
	@echo "Open $(PAPER).pdf in your viewer of choice."

watch:
	@echo "Re-run 'make all' on edits."
