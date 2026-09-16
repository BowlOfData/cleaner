"""Generate the LaTeX corpus.

The fixture is built to be hostile. Every construct here is one a naive
implementation gets wrong: an escaped percent, a percent inside a listing, a
percent inside a URL, a comment whose removal would change the typeset output,
a CRLF region, and content hidden after \\endinput.
"""

from pathlib import Path

CORPUS = Path(__file__).resolve().parent.parent

PAPER = rb"""% !TeX root = /Users/marco/thesis/paper.tex
% !TeX program = pdflatex
\documentclass{article}
\usepackage{listings}
\usepackage{hyperref}
\usepackage{changes}

\author{Marco Parrillo\thanks{Initech Holdings}}
\date{2024-03-11}
\email{marco@example.invalid}
\hypersetup{
  pdftitle={Quarterly numbers},
  pdfauthor={Marco Parrillo},
  pdfcreator={ACME Writer 9},
  pdfsubject={internal},
  colorlinks=true,
  dcterms:provenance={https://example.invalid/manifest.c2pa}
}

\begin{document}
\maketitle

Revenue was flat. Margin rose 100\% year on year.

See \url{https://example.invalid/a%20b/c} and \href{https://x.invalid/%41}{the note}.

\includegraphics{/Users/marco/Desktop/figure.png}

\newcommand{\joined}{tight}%  a trailing comment that eats the newline
   follows immediately.

\begin{lstlisting}
# 50% of the time it works every time
print("\verb is inert here")
\end{lstlisting}

Inline \verb|100%| and \lstinline{a % b} stay put.

\added[id=MP]{New paragraph.}
\deleted[id=DW]{Old paragraph.}
\todo[author=MP]{check this before submitting}

\begin{comment}
Reviewer 2 is wrong and I will say so in the rebuttal.
\end{comment}

\end{document}
\endinput
Draft notes nobody was meant to read: the Initech deal closes in April.
"""

INTRO = rb"""\section{Introduction}
% drafted by Marco Parrillo, do not circulate
Text.
"""


PKG = rb"""%% mypkg.sty -- helpers for the quarterly report
%% Copyright 2024 Marco Parrillo
%% This work may be distributed under the LaTeX Project Public License.
\NeedsTeXFormat{LaTeX2e}
\ProvidesPackage{mypkg}[2024/03/11 v1.0 helpers]
\author{Marco Parrillo}
\newcommand{\tag}{x}   % internal: Marco to rewrite before release
"""

REFS = rb"""@article{smith2024,
  author    = {Smith, Jane and Doe, John},
  title     = {A Study of 50% Efficiency},
  year      = {2024},
  url       = {https://example.invalid/a%20b},
  file      = {/Users/marco/Zotero/storage/ABC/Smith 2024.pdf},
  bdsk-file-1 = {YnBsaXN0MDDSAQIDBFxyZWxhdGl2ZVBhdGg=},
  owner     = {marco},
  timestamp = {2024-03-11},
  note      = {Quoted, with a comma "inside"},
}
"""

DOC = rb"""% \iffalse
%<*driver>
\documentclass{ltxdoc}
%</driver>
% \fi
% \section{Documentation}
% This prose is the document itself. A 100% literal percent lives here.
% Written by Marco Parrillo.
\def\tag{x}   % a real code comment
\author{Marco Parrillo}
"""


def main() -> None:
    (CORPUS / "paper.tex").write_bytes(PAPER)
    (CORPUS / "mypkg.sty").write_bytes(PKG)
    (CORPUS / "refs.bib").write_bytes(REFS)
    (CORPUS / "doc.dtx").write_bytes(DOC)

    crlf = CORPUS / "crlf.tex"
    crlf.write_bytes(rb"\documentclass{article}" + b"\r\n"
                     + b"% a note\r\n"
                     + rb"\author{Marco Parrillo}" + b"\r\n")

    latin = CORPUS / "latin1.tex"
    latin.write_bytes(rb"\documentclass{article}" + b"\n"
                      + "% caf\xe9 note".encode("latin-1") + b"\n"
                      + "\\author{Ren\xe9 Dupont}".encode("latin-1") + b"\n")

    catcode = CORPUS / "catcode.tex"
    catcode.write_bytes(rb"\documentclass{article}" + b"\n"
                        + rb"\catcode`\%=12" + b"\n"
                        + rb"\author{Marco Parrillo}" + b"\n")

    for sub in ("sections", "appendix"):
        target = CORPUS / "project" / sub
        target.mkdir(parents=True, exist_ok=True)
        (target / "intro.tex").write_bytes(INTRO)

    print("wrote paper.tex, mypkg.sty, refs.bib, doc.dtx, crlf.tex, latin1.tex, catcode.tex, project/*/intro.tex")


if __name__ == "__main__":
    main()
