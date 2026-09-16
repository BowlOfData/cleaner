"""Generate unsigned PDF and DOCX fixtures carrying identifying metadata."""
import pathlib, zipfile, datetime

GEN = pathlib.Path(__file__).parent
OUT = GEN.parent

def make_pdf():
    import pikepdf
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    with pdf.open_metadata() as meta:
        meta["dc:creator"] = ["Marco Parrillo"]
        meta["dc:title"] = "Quarterly numbers"
        meta["xmp:CreatorTool"] = "ACME Writer 9"
        meta["xmpMM:DocumentID"] = "uuid:11111111-2222-3333-4444-555555555555"
    pdf.docinfo["/Author"] = "Marco Parrillo"
    pdf.docinfo["/Creator"] = "ACME Writer 9"
    pdf.docinfo["/Producer"] = "ACME PDF Engine 3.1"
    pdf.docinfo["/Keywords"] = "internal, draft"
    pdf.docinfo["/CreationDate"] = "D:20260822120000Z"
    pdf.save(OUT / "doc.pdf")
    print("wrote doc.pdf")

CORE = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>Quarterly numbers</dc:title><dc:creator>Marco Parrillo</dc:creator><cp:lastModifiedBy>Dana Whitfield</cp:lastModifiedBy><cp:revision>7</cp:revision><dcterms:created xsi:type="dcterms:W3CDTF">2026-08-01T09:00:00Z</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">2026-08-22T12:00:00Z</dcterms:modified></cp:coreProperties>'''

APP = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>ACME Words</Application><Company>Initech Holdings</Company><Manager>Dana Whitfield</Manager><TotalTime>412</TotalTime></Properties>'''

DOCUMENT = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Revenue was flat.</w:t></w:r></w:p><w:ins w:id="1" w:author="Dana Whitfield" w:date="2026-08-20T10:00:00Z"><w:r><w:t> Actually it fell.</w:t></w:r></w:ins></w:body></w:document>'''

SETTINGS = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:rsids><w:rsidRoot w:val="00AB12CD"/><w:rsid w:val="00AB12CD"/><w:rsid w:val="00EF34AB"/></w:rsids></w:settings>'''

CONTENT_TYPES = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'''

RELS = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'''

def make_docx():
    path = OUT / "doc.docx"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", CONTENT_TYPES)
        z.writestr("_rels/.rels", RELS)
        z.writestr("word/document.xml", DOCUMENT)
        z.writestr("word/settings.xml", SETTINGS)
        z.writestr("docProps/core.xml", CORE)
        z.writestr("docProps/app.xml", APP)
    print("wrote doc.docx")

if __name__ == "__main__":
    make_pdf()
    make_docx()
