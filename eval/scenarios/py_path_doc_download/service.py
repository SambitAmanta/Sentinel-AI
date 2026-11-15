"""Document service layer."""
from download import init_docs, get_document

def fetch_doc_content(filename: str) -> str:
    init_docs()
    return get_document(filename)

