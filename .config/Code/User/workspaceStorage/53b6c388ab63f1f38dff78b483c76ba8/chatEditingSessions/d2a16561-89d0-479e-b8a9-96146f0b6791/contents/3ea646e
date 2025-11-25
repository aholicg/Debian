# AI Model Integration Guide

## Overview
You need to replace the hardcoded demo JSON (`getRandomDemoJson`) in `mAIware/scanner-worker.js` with real predictions from the Python AI model in `mAIware---AI/`.

---

## Current Architecture

### What Happens Now (Hardcoded Demo)
1. **File detected** → `scanner-worker.js` receives a PE file
2. **PE check** → Uses `determinePeStatus()` to verify it's a PE
3. **Demo result** → Calls `getRandomDemoJson()` which returns fake classification
4. **UI displays** → Shows the demo data with random confidence scores

### Expected Output Format
The current system expects this JSON structure:
```json
{
  "detected_filename": "malware.exe",
  "file_hashes": {
    "sha256": "abc123...",
    "md5": "def456..."
  },
  "classification": "Malware",  // "Benign", "Suspicious", or "Malware"
  "malware_family": "Trojan.Downloader.Win32",  // optional
  "confidence_score": 0.85,  // 0.0 to 1.0
  "vendor": {
    "name": "Windows Defender",
    "icon": "fas fa-shield-alt"
  },
  "key_findings": {
    "file_type": "PE32 Executable",
    "packer_detected": "None",
    "signature": {
      "name": "Microsoft Corporation",
      "icon": "fas fa-check-circle",
      "level": "verified"
    },
    "section_entropy": [
      { "name": ".text", "entropy": 6.5 },
      { "name": ".data", "entropy": 3.2 }
    ],
    "api_imports": ["CreateRemoteThread", "VirtualAllocEx"],
    "key_strings": ["http://malicious.com", "cmd.exe"]
  }
}
```

---

## AI Model Output Format

The AI model outputs a CSV with these columns:
```csv
sample_name,ensemble_class,ensemble_score
malware.exe,malware,0.85
```

Where:
- `ensemble_class`: "benign", "suspicious", or "malware"
- `ensemble_score`: probability score (0.0 - 1.0)

---

## Integration Strategy

### Option 1: Python Child Process (Recommended)
Call the Python script directly from Node.js for each file.

**Pros:**
- Simple integration
- No server needed
- Real-time predictions

**Cons:**
- Slower (Python startup overhead)
- Requires Python + dependencies on client machine

### Option 2: Python HTTP Service
Run the AI model as a separate HTTP server.

**Pros:**
- Faster (model stays loaded)
- Clean separation of concerns
- Can handle multiple requests

**Cons:**
- More complex setup
- Need to manage Python process

### Option 3: ONNX Runtime (Advanced)
Convert models to ONNX and run directly in Node.js.

**Pros:**
- Fastest
- No Python dependency

**Cons:**
- Complex conversion
- May lose model accuracy

---

## Implementation Steps (Option 1 - Child Process)

### Step 1: Create Python Prediction Wrapper

Create `mAIware---AI/predict_single.py`:

```python
#!/usr/bin/env python3
"""Predict a single PE file and output JSON."""
import json
import sys
from pathlib import Path
from ensemble_predict_dir import (
    load_model_columns, extract_features, prepare_feature_matrix,
    run_models, DEFAULT_MODELS_DIR, DEFAULT_MODEL_COLS, DEFAULT_MODELS
)
from ensemble_vote import run_majority_voting
from classification_utils import classify_probability

def predict_single_file(file_path: Path) -> dict:
    """Predict a single file and return result dict."""
    model_cols = load_model_columns(DEFAULT_MODEL_COLS)
    
    # Extract features
    features_df = extract_features([file_path], model_cols)
    if features_df.empty:
        return {
            "error": "Failed to extract features",
            "classification": "suspicious",
            "confidence_score": 0.5
        }
    
    feature_matrix = prepare_feature_matrix(features_df, model_cols)
    
    # Run models
    predictions_df = run_models(feature_matrix, DEFAULT_MODELS, DEFAULT_MODELS_DIR)
    voting_df, _ = run_majority_voting(predictions_df, DEFAULT_MODELS)
    
    # Get result
    row = voting_df.iloc[0]
    ensemble_class = row.get('ensemble_class', 'suspicious')
    ensemble_score = float(row.get('ensemble_score', 0.5))
    
    return {
        "classification": ensemble_class.capitalize(),  # Benign/Suspicious/Malware
        "confidence_score": ensemble_score,
        "votes_benign": int(row.get('votes_benign', 0)),
        "votes_malware": int(row.get('votes_malware', 0))
    }

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No file path provided"}))
        sys.exit(1)
    
    file_path = Path(sys.argv[1])
    if not file_path.exists():
        print(json.dumps({"error": "File not found"}))
        sys.exit(1)
    
    try:
        result = predict_single_file(file_path)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e), "classification": "suspicious", "confidence_score": 0.5}))
        sys.exit(1)
```

### Step 2: Create Node.js AI Client

Create `mAIware/ai-client.js`:

```javascript
const { spawn } = require('node:child_process');
const path = require('node:path');

const AI_MODEL_DIR = path.join(__dirname, '..', 'mAIware---AI');
const PYTHON_SCRIPT = path.join(AI_MODEL_DIR, 'predict_single.py');

/**
 * Call AI model to classify a PE file
 * @param {string} filePath - Absolute path to the PE file
 * @returns {Promise<object>} - Classification result
 */
async function classifyWithAI(filePath) {
  return new Promise((resolve, reject) => {
    const python = spawn('python3', [PYTHON_SCRIPT, filePath], {
      cwd: AI_MODEL_DIR
    });

    let stdout = '';
    let stderr = '';

    python.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    python.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    python.on('close', (code) => {
      if (code !== 0) {
        console.error('[AI] Python error:', stderr);
        // Return suspicious as fallback
        resolve({
          classification: 'Suspicious',
          confidence_score: 0.5,
          error: 'AI model failed'
        });
        return;
      }

      try {
        const result = JSON.parse(stdout.trim());
        resolve(result);
      } catch (err) {
        console.error('[AI] Failed to parse JSON:', stdout);
        resolve({
          classification: 'Suspicious',
          confidence_score: 0.5,
          error: 'Invalid AI response'
        });
      }
    });

    python.on('error', (err) => {
      console.error('[AI] Failed to spawn Python:', err);
      resolve({
        classification: 'Suspicious',
        confidence_score: 0.5,
        error: 'Python not available'
      });
    });
  });
}

module.exports = { classifyWithAI };
```

### Step 3: Modify scanner-worker.js

Replace the demo JSON generation with real AI predictions:

**Find this section** (around line 385):
```javascript
} else {
  scanResult = getRandomDemoJson(detectedFilename, fileHashes)
  scanResult.is_pe = true
}
```

**Replace with:**
```javascript
} else {
  // Call real AI model instead of demo
  const { classifyWithAI } = require('./ai-client');
  const aiResult = await classifyWithAI(filePath);
  
  // Build result with AI prediction + demo metadata
  scanResult = {
    detected_filename: detectedFilename,
    file_hashes: fileHashes,
    classification: aiResult.classification,
    confidence_score: aiResult.confidence_score,
    is_pe: true,
    vendor: {
      name: "mAIware AI Engine",
      icon: "fas fa-brain"
    },
    key_findings: {
      file_type: "PE32 Executable",
      packer_detected: "Unknown",
      signature: {
        name: "Not Signed",
        icon: "fas fa-question-circle",
        level: "unknown"
      },
      section_entropy: [],
      api_imports: [],
      key_strings: []
    }
  };
  
  // Add AI-specific metadata if available
  if (aiResult.votes_benign !== undefined) {
    scanResult.ai_votes = {
      benign: aiResult.votes_benign,
      malware: aiResult.votes_malware
    };
  }
}
```

### Step 4: Install Python Dependencies

```bash
cd /home/trang/localnsv/mAIware---AI
pip install -r requirements.txt
```

### Step 5: Download AI Models

Follow the README instructions:
1. Go to https://github.com/vuquangtien/mAIware---AI/releases
2. Download `ensemble_models.zip`
3. Extract to `mAIware---AI/ensemble_models/`

---

## Enhanced Version: Add Real PE Metadata

To make the result richer, you can extract real PE metadata using `pefile`:

**Install pefile in Node.js:**
```bash
cd /home/trang/localnsv/mAIware
npm install pe-library  # Already installed
```

**Modify ai-client.js to include PE metadata extraction:**

```javascript
const peParser = require('pe-library');

async function extractPeMetadata(filePath) {
  try {
    const data = await fs.promises.readFile(filePath);
    const pe = peParser.NtExecutable.from(data);
    
    // Extract sections and calculate entropy
    const sections = [];
    if (pe.sections) {
      for (const section of pe.sections) {
        sections.push({
          name: section.name,
          entropy: calculateEntropy(section.data)
        });
      }
    }
    
    return {
      sections,
      fileType: pe.is64Bit ? 'PE64 Executable' : 'PE32 Executable',
      // Add more metadata as needed
    };
  } catch (err) {
    return {
      sections: [],
      fileType: 'PE Executable'
    };
  }
}

function calculateEntropy(data) {
  if (!data || data.length === 0) return 0;
  const freq = {};
  for (const byte of data) {
    freq[byte] = (freq[byte] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / data.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
```

Then combine AI prediction with PE metadata:

```javascript
const aiResult = await classifyWithAI(filePath);
const peMetadata = await extractPeMetadata(filePath);

scanResult = {
  detected_filename: detectedFilename,
  file_hashes: fileHashes,
  classification: aiResult.classification,
  confidence_score: aiResult.confidence_score,
  is_pe: true,
  vendor: { name: "mAIware AI", icon: "fas fa-brain" },
  key_findings: {
    file_type: peMetadata.fileType,
    packer_detected: "Unknown",
    signature: { name: "Not Signed", icon: "fas fa-question-circle", level: "unknown" },
    section_entropy: peMetadata.sections,
    api_imports: [],
    key_strings: []
  }
};
```

---

## Testing the Integration

1. **Test Python script directly:**
```bash
cd /home/trang/localnsv/mAIware---AI
python3 predict_single.py samples/your_file.exe
```

2. **Test Node.js integration:**
```javascript
// In scanner-worker.js, add logging
postLog(`[AI] Calling AI model for ${filePath}`);
const aiResult = await classifyWithAI(filePath);
postLog(`[AI] Result: ${JSON.stringify(aiResult)}`);
```

3. **Verify output format:**
- Check that classification is "Benign", "Suspicious", or "Malware"
- Check that confidence_score is between 0 and 1
- Ensure UI displays correctly

---

## Fallback Strategy

Always have a fallback if AI fails:

```javascript
const { classifyWithAI } = require('./ai-client');
const { getRandomDemoJson } = require('./jsonsamples');

let aiResult;
try {
  aiResult = await classifyWithAI(filePath);
  if (aiResult.error) {
    postLog(`[AI] Error, using demo: ${aiResult.error}`);
    scanResult = getRandomDemoJson(detectedFilename, fileHashes);
  } else {
    // Build scanResult with AI data
  }
} catch (err) {
  postError(`[AI] Exception: ${err.message}`);
  scanResult = getRandomDemoJson(detectedFilename, fileHashes);
}
```

---

## Performance Considerations

- **Cold start:** First prediction takes ~5-10 seconds (model loading)
- **Subsequent:** ~2-3 seconds per file
- **Optimization:** Consider Option 2 (HTTP service) for better performance

---

## Summary

**Minimal changes needed:**
1. Create `mAIware---AI/predict_single.py` wrapper
2. Create `mAIware/ai-client.js` Node.js client
3. Modify `scanner-worker.js` line ~385 to call `classifyWithAI()`
4. Keep fallback to demo JSON if AI fails

**Result:** Real AI predictions instead of hardcoded demo data!
