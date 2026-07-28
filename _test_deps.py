
import sys
print("Python:", sys.version, file=sys.stderr)
try:
    import spacy
    print("spaCy:", spacy.__version__, file=sys.stderr)
except ImportError as e:
    print("spaCy MISSING:", e, file=sys.stderr)
try:
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    print("NlpEngineProvider: OK", file=sys.stderr)
except ImportError as e:
    print("NlpEngineProvider MISSING:", e, file=sys.stderr)
