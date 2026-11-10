# Machine-Learning-Security

# Machine Learning for Security

Machine learning projects for network intrusion and malware detection, developed for ENPM604 (Machine Learning for Cybersecurity), University of Maryland.

## 1. NSL-KDD Network Intrusion Detection
**File:** `ApproxAgglomerativeKDD.py`

Unsupervised clustering of network traffic from the NSL-KDD dataset to separate normal connections from attacks without labeled training data.
- Filters the dataset to continuous features by parsing the KDD feature definitions
- Computes Euclidean distance between connection records and groups them with approximate agglomerative clustering
- Visualizes traffic with PCA, colored by attack category (DoS, Probe, R2L, U2R, normal)

Data: [NSL-KDD dataset](https://www.unb.ca/cic/datasets/nsl.html). Place the files in a folder named `NSL-KDD` next to the script.

## 2. ML-Based Malware Detection
**Files:** `DisassemblyMnemonicNgramGenerator.py`, `ApproxAgglomerativeClustering.py`, `PrototypeMalwareDetector.py`

Prototype malware detector built on instruction-level features from disassembled binaries.
1. **DisassemblyMnemonicNgramGenerator.py**: extracts instruction-mnemonic n-grams from disassembled binaries
2. **ApproxAgglomerativeClustering.py**: clusters samples by Jaccard similarity of their n-gram sets
3. **PrototypeMalwareDetector.py**: classifies new samples against cluster prototypes

No malware samples are included in this repository.

## Tools
Python, NumPy, scikit-learn, Matplotlib, n-gram feature extraction, Jaccard similarity, agglomerative clustering
