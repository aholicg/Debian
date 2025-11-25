#!/usr/bin/env python3
"""Predict a single PE file and output comprehensive JSON with features."""
import json
import sys
from pathlib import Path
import pefile

from ensemble_predict_dir import (
    load_model_columns, extract_features, prepare_feature_matrix,
    run_models, DEFAULT_MODELS_DIR, DEFAULT_MODEL_COLS, DEFAULT_MODELS
)
from ensemble_vote import run_majority_voting
import pe_to_features

# Import angr for call graph extraction (optional)
try:
    import angr
    import networkx as nx
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    print("Warning: angr not available, call graph extraction disabled", file=sys.stderr)


def extract_pe_sections(file_path: Path) -> list:
    """Extract section names and entropy from PE file."""
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        sections = []
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            data = section.get_data() or b''
            section_entropy = pe_to_features.entropy(data)
            sections.append({
                'name': name,
                'entropy': round(section_entropy, 2),
                'size': len(data)
            })
        pe.close()
        return sections
    except Exception as e:
        print(f"Warning: Failed to extract sections: {e}", file=sys.stderr)
        return []


def extract_pe_imports(file_path: Path) -> list:
    """Extract imported DLL and function names."""
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
        ])
        
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports[:5]:  # Limit to first 5 per DLL
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        imports.append(func_name)
        pe.close()
        return imports[:20]  # Limit total to 20
    except Exception as e:
        print(f"Warning: Failed to extract imports: {e}", file=sys.stderr)
        return []


def extract_pe_strings(file_path: Path, max_strings: int = 10) -> list:
    """Extract interesting strings from PE file."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Simple string extraction (ASCII printable, min length 4)
        strings = []
        current = []
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= 4:
                    s = ''.join(current)
                    # Filter interesting strings
                    interesting_keywords = ['http', 'www', '.exe', '.dll', 'cmd', 'shell', 
                                          'download', 'install', 'registry', 'temp', 'system']
                    if any(kw in s.lower() for kw in interesting_keywords):
                        strings.append(s)
                        if len(strings) >= max_strings:
                            break
                current = []
        
        return strings[:max_strings]
    except Exception as e:
        print(f"Warning: Failed to extract strings: {e}", file=sys.stderr)
        return []


def get_pe_type(file_path: Path) -> str:
    """Determine PE type (PE32/PE32+)."""
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        if pe.OPTIONAL_HEADER.Magic == 0x20b:
            result = 'PE64 Executable (PE32+)'
        elif pe.OPTIONAL_HEADER.Magic == 0x10b:
            result = 'PE32 Executable'
        else:
            result = 'PE Executable'
        
        # Check if it's a DLL
        if pe.FILE_HEADER.Characteristics & 0x2000:
            result = result.replace('Executable', 'DLL')
        
        pe.close()
        return result
    except Exception:
        return 'PE Executable'


def detect_packer(file_path: Path, sections: list) -> str:
    """Detect common packers based on section names and entropy."""
    try:
        # Check for high entropy sections (packed indicator)
        high_entropy_sections = [s for s in sections if s.get('entropy', 0) > 7.5]
        
        # Check for common packer section names
        section_names = [s.get('name', '').upper() for s in sections]
        
        if 'UPX0' in section_names or 'UPX1' in section_names:
            return 'UPX'
        elif '.aspack' in [s.lower() for s in section_names]:
            return 'ASPack'
        elif '.petite' in [s.lower() for s in section_names]:
            return 'Petite'
        elif len(high_entropy_sections) >= 2:
            return 'Possibly Packed (High Entropy)'
        elif len(high_entropy_sections) == 1:
            return 'Suspicious (Partial Packing)'
        else:
            return 'None Detected'
    except Exception:
        return 'Unknown'


def extract_callgraph_json(file_path: Path, max_nodes: int = 15) -> dict:
    """Extract call graph using angr and return JSON structure for UI."""
    if not ANGR_AVAILABLE:
        return {"error": "angr not available", "nodes": [], "edges": []}
    
    try:
        print(f"[*] Extracting call graph from {file_path.name}...", file=sys.stderr)
        
        # Load binary with angr
        proj = angr.Project(str(file_path), auto_load_libs=False, load_debug_info=False)
        
        # Build CFG (fast mode)
        cfg = proj.analyses.CFGFast()
        
        # Find entry function
        entry_func = None
        if proj.entry in cfg.kb.functions:
            entry_func = cfg.kb.functions[proj.entry]
        else:
            for f in cfg.kb.functions.values():
                try:
                    if f.contains_addr(proj.entry):
                        entry_func = f
                        break
                except Exception:
                    continue
        
        if entry_func is None:
            return {"error": "No entry function found", "nodes": [], "edges": []}
        
        # Get call graph and limit nodes using BFS
        callgraph = cfg.kb.callgraph
        start_addr = entry_func.addr
        
        if start_addr not in callgraph:
            return {"error": "Entry not in call graph", "nodes": [], "edges": []}
        
        # BFS to select limited nodes
        selected = set()
        queue = [start_addr]
        
        while queue and len(selected) < max_nodes:
            node = queue.pop(0)
            if node in selected:
                continue
            selected.add(node)
            
            # Add successors and predecessors
            for successor in callgraph.successors(node):
                if successor not in selected and successor not in queue:
                    if len(selected) + len(queue) < max_nodes:
                        queue.append(successor)
            
            for predecessor in callgraph.predecessors(node):
                if predecessor not in selected and predecessor not in queue:
                    if len(selected) + len(queue) < max_nodes:
                        queue.append(predecessor)
        
        # Build subgraph
        subgraph = callgraph.subgraph(selected)
        
        # Convert to JSON format for UI
        nodes = []
        edges = []
        
        for addr in subgraph.nodes():
            func = cfg.kb.functions.get(addr)
            if func and func.name:
                name = func.name
            else:
                name = f"sub_{hex(addr)[2:]}"
            
            # Classify node type
            node_class = "node-std"
            if addr == start_addr:
                node_class = "node-entry"
            elif any(suspicious in name.lower() for suspicious in 
                    ["inject", "allocate", "remote", "virtual", "create", "write", "exec"]):
                node_class = "node-malicious"
            
            nodes.append({
                "id": hex(addr),
                "label": name,
                "class": node_class,
                "address": hex(addr)
            })
        
        for src, dst in subgraph.edges():
            edges.append({
                "from": hex(src),
                "to": hex(dst)
            })
        
        print(f"[*] Extracted {len(nodes)} nodes and {len(edges)} edges", file=sys.stderr)
        return {"nodes": nodes, "edges": edges}
        
    except Exception as e:
        print(f"[!] Call graph extraction failed: {e}", file=sys.stderr)
        return {"error": str(e), "nodes": [], "edges": []}


def predict_single_file(file_path: Path) -> dict:
    """Predict a single file and return comprehensive result dict."""
    try:
        model_cols = load_model_columns(DEFAULT_MODEL_COLS)
        
        # Extract features
        features_df = extract_features([file_path], model_cols)
        if features_df.empty:
            return {
                "error": "Failed to extract features",
                "classification": "Suspicious",
                "confidence_score": 0.5
            }
        
        feature_matrix = prepare_feature_matrix(features_df, model_cols)
        
        # Run models
        predictions_df = run_models(feature_matrix, DEFAULT_MODELS, DEFAULT_MODELS_DIR)
        voting_df, _ = run_majority_voting(predictions_df, DEFAULT_MODELS)
        
        # Get ensemble result
        row = voting_df.iloc[0]
        ensemble_class = row.get('ensemble_class', 'suspicious')
        ensemble_score = float(row.get('ensemble_score', 0.5))
        
        # Extract PE metadata
        sections = extract_pe_sections(file_path)
        imports = extract_pe_imports(file_path)
        strings = extract_pe_strings(file_path)
        file_type = get_pe_type(file_path)
        packer = detect_packer(file_path, sections)
        
        # Get feature values for additional context
        feature_row = features_df.iloc[0]
        
        # Extract call graph (optional, can be slow)
        callgraph_data = extract_callgraph_json(file_path, max_nodes=15)
        
        result = {
            "classification": ensemble_class.capitalize(),  # Benign/Suspicious/Malware
            "confidence_score": round(ensemble_score, 2),
            "votes_benign": int(row.get('votes_benign', 0)),
            "votes_malware": int(row.get('votes_malware', 0)),
            "ensemble_label": int(row.get('ensemble_label', 0)),  # 0=benign, 1=malware
            "ensemble_score": round(ensemble_score, 2),
            "ensemble_class": ensemble_class,  # benign/suspicious/malware
            "ensemble_class_id": int(row.get('ensemble_class_id', 1)),  # 0/1/2
            "file_type": file_type,
            "packer_detected": packer,
            "section_entropy": sections,
            "api_imports": imports,
            "key_strings": strings,
            "call_graph": callgraph_data,
            "pe_features": {
                "file_size": int(feature_row.get('FileSize', 0)),
                "entropy_total": round(float(feature_row.get('Entropy_Total', 0)), 2),
                "number_of_sections": int(feature_row.get('NumberOfSections', 0)),
                "total_dlls": int(feature_row.get('Total_DLLs', 0)),
                "total_resources": int(feature_row.get('Total_Resources', 0)),
                "is_packed": int(feature_row.get('Packed', 0)) == 1
            }
        }
        
        return result
        
    except Exception as e:
        print(f"Error during prediction: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return {
            "error": str(e),
            "classification": "Suspicious",
            "confidence_score": 0.5
        }


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No file path provided"}))
        sys.exit(1)
    
    file_path = Path(sys.argv[1])
    if not file_path.exists():
        print(json.dumps({"error": "File not found"}))
        sys.exit(1)
    
    result = predict_single_file(file_path)
    print(json.dumps(result, indent=2))
