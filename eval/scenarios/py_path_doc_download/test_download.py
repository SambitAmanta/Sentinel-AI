from service import fetch_doc_content

def test_fetch_document():
    content = fetch_doc_content("invoice.pdf")
    assert content == "INVOICE_CONTENT"

