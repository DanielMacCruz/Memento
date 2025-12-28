---
description: Analyze database leak folders and extract Brazilian passwords using AI-assisted format detection
---

# Brazilian Password Mining Workflow

This workflow extracts Brazilian passwords from the Raidforums database leak collection (~400GB).

## Overview

The data contains 150+ folders with different formats. Most require AI analysis to determine:
1. Is there a password field?
2. Is it plaintext or hashed?
3. What's the exact parsing pattern?

## Prerequisites

- Python 3.8+
- Google Gemini API key (for cheap batch analysis) OR OpenAI API key
- Access to the Raidforums data at `/run/media/kozi/HDD4TB/New folder/Database Leaks/DATABASES/Raidforums`

## Workflow Steps

### Step 1: Generate Folder Samples

// turbo
```bash
cd /home/kozi/sniff
python3 br_analyzer.py
```

This creates `/run/media/kozi/HDD4TB/New folder/BR_ANALYSIS.txt` with:
- Sample lines from each folder
- Brazilian email samples
- Detected delimiter
- Initial parsing guess

### Step 2: AI Batch Analysis

Run the AI analyzer to classify each folder:

```bash
cd /home/kozi/sniff
python3 br_ai_classifier.py --api-key YOUR_GEMINI_API_KEY
```

This sends each folder's sample to Gemini Flash and gets back:
- `SKIP` - No plaintext passwords (hashed, no passwords, non-BR)
- `PARSE` - Has plaintext passwords with extraction pattern
- `MANUAL` - Needs human review

Output: `/run/media/kozi/HDD4TB/New folder/BR_CLASSIFICATION.json`

### Step 3: Extract Passwords

Run extraction only on classified PARSE folders:

```bash
cd /home/kozi/sniff  
python3 br_extractor.py --classification BR_CLASSIFICATION.json
```

Output: `/run/media/kozi/HDD4TB/New folder/BIG_BR_DUMP.txt`

### Step 4: Quality Check

Sample and verify the output:

// turbo
```bash
shuf /run/media/kozi/HDD4TB/New\ folder/BIG_BR_DUMP.txt | head -100
```

## Known Good Folders (Confirmed Plaintext)

| Folder | Format | Password Field |
|--------|--------|----------------|
| 000Webhost.com | `name:email:ip:password` | Last field |
| Brazzers.com | `email:username:password` | Last field |

## Known Bad Folders (Skip)

| Folder | Reason |
|--------|--------|
| LinkedIn.com | SHA1 hashed |
| Dropbox.com | SHA1/MD5 hashed |
| Myspace.com | Hashed |
| Edmodo.com | bcrypt + MD5 |
| Disqus.com | SHA1 hashed |
| Modbsolutions.com | NO PASSWORDS (CRM data) |
| All .cn/.ru sites | Non-Brazilian |
| Voter Databases | No passwords |

## Files

- `br_analyzer.py` - Generates sample analysis file
- `br_ai_classifier.py` - Sends samples to AI for classification  
- `br_extractor.py` - Extracts passwords based on classification
- `BR_ANALYSIS.txt` - Raw folder samples
- `BR_CLASSIFICATION.json` - AI classification results
