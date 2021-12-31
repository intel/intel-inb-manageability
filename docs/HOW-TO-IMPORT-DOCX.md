# How to import from .docx format

Install pandoc using your package manager. The pandoc home page is here: https://pandoc.org/

To convert a .docx file to .md in a format that works well with GitHub: `pandoc -s -f docx document1.docx --extract-media=media/document1 -t markdown_mmd -o document1.md`
