# Research intelligence pack

TraceAtlas ships an offline, metadata-only research pack generated from the supplied
`OSINT_Prior_Art_Master_5900_and_Gap_Analysis_1000` workbook. It is a search and
design-support layer, not a claim that TraceAtlas reproduces every paper.

## Audited input

- 5,900 master records: 5,400 papers and 500 patent publications.
- 5,375 paper rows passed basic title, locator and pre-2027 checks.
- 5,249 remained after normalized-title deduplication.
- Exactly 4,096 papers were selected with proportional coverage across all 16
  supplied subtopics. Every research ID cited by the 1,000 gap hypotheses is
  present in the selected pack.
- The pack also includes 500 patent metadata rows, 1,000 gap hypotheses and 959
  fully resolvable research/patent title-overlap leads. Forty-one source match
  rows referencing 19 papers removed by quality screening or title deduplication
  are excluded and counted in the manifest.

Long abstracts, workbook comments, formulas and the review-assignment worksheet are
not published. The manifest records the source SHA-256, selection method, dataset
hashes and record counts. `traceatlas research status --verify` verifies the installed
copy.

## Commands

```bash
./start.sh research status --verify
./start.sh research search "entity resolution provenance" --limit 10
./start.sh research gaps "privacy-preserving cross-platform correlation"
./start.sh research plan --objective "real-time evidence provenance"
./start.sh research prior-art --paper-id RES-NEW-01645
```

The same interface is installed as `traceatlas-research`.

`search` uses BM25-style relevance scoring and optional maximal-marginal-relevance
reranking so a result list is not dominated by near-identical titles. Each result
contains matched terms and the original DOI/URL. `gaps` and `plan` preserve the
workbook's caveat that metadata underrepresentation is not proof of novelty,
patentability, freedom to operate or demand.

Two local analysis methods are also included:

```bash
./start.sh research match --left public-a.json --right public-b.json
./start.sh research timeline --file claims.json --as-of 2026-09-25
```

Entity matching accepts only non-sensitive public labels, returns field-level
similarities, never merges records and always requires review. Timeline analysis
detects overlapping contradictory values and calculates transparent exponential
freshness decay. Freshness is not a truth score.

## Rebuild

```bash
python scripts/build_research_pack.py /path/to/source.xlsx \
  --output src/traceatlas/research/data --papers 4096 --max-year 2026
```

The builder uses only the Python standard library. It deliberately ignores personal
review assignments and emits deterministic gzip files (`mtime=0`).

## Method references

- Robertson and Zaragoza, *The Probabilistic Relevance Framework: BM25 and
  Beyond*, DOI `10.1561/1500000019`.
- Carbonell and Goldstein, *The Use of MMR, Diversity-Based Reranking for
  Reordering Documents and Producing Summaries*, DOI `10.1145/290941.291025`.
- Fellegi and Sunter, *A Theory for Record Linkage*, DOI
  `10.1080/01621459.1969.10501049`.
- Li and Croft, *Time-Based Language Models*, DOI `10.1145/956863.956951`.
- W3C PROV-O Recommendation and OASIS STIX 2.1 are the interoperability references
  for provenance and CTI representation. TraceAtlas does not claim conformance for
  formats it does not export.

These references inform bounded algorithms and interface choices. The implementation
is independently written, dependency-free and tested; it is not presented as an exact
reproduction of experimental systems in the cited literature.
