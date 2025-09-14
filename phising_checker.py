import os
import pandas as pd
from pymongo import MongoClient
from datetime import datetime


def rules_loading(file_path):
    if not os.path.exists(file_path):
        print(f"file not found: {file_path}")
        return []
    try:
        df = pd.read_excel(file_path)
    except Exception as e:
        print(f"Error reading excel file: {e}")
        return []
    rules = []
    for _, row in df.iterrows():
        start = str(row.get("start", "")).strip()
        end = str(row.get("end", "")).strip()
        phrase = str(row.get("phrase", "")).strip().lower()
        if start and end and phrase:
            rules.append({"start": start, "end": end, "phrase": phrase})
    print(f"Loaded the  {len(rules)} rules from '{file_path}'")
    if len(rules) > 0:
        for r in rules[:10]:
            print(f"start: '{r['start']}'  end: '{r['end']}'  phrase: '{r['phrase']}'")
    return rules


def email_loading(file_path):
    if not os.path.exists(file_path):
        print(f"Email not found: {file_path}")
        return []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            print(f"Loaded email '{file_path}' with {len(lines)} lines")
            return lines
    except Exception as e:
        print(f"Error reading email : {e}")
        return []


def segment_Extraction(email_lines, start_tag, end_tag):
    inside = False
    segment = []
    start_line = 0
    for i, line in enumerate(email_lines, start=1):
        low = line.lower()
        if start_tag.lower() in low and not inside:
            inside = True
            start_line = i
        if inside:
            segment.append(line)
        if end_tag.lower() in low and inside:
            break
    segment_text = "".join(segment).lower()
    return start_line, segment_text


def phishingParts_checking(segment_text, rules):
    found_phrases = []
    if not segment_text:
        return found_phrases
    for rule in rules:
        if rule["phrase"] in segment_text:
            found_phrases.append(rule["phrase"])
    return found_phrases


if __name__ == "__main__":
    try:
        RULE_FILE = "setup.xlsx"
        EMAIL_FILE = "sample.eml"

        # connect to MongoDB (Atlas or Local)
        MONGO_URI = "mongodb+srv://darshana:Meekiri213@cluster0.bmrclmi.mongodb.net/SmartBuild?retryWrites=true&w=majority&appName=Cluster0"  # e.g., mongodb+srv://user:pass@cluster0.mongodb.net/
        DB_NAME = "SmartBuild"
        COLLECTION_NAME = "phishing_results"

        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]

        # load
        rules = rules_loading(RULE_FILE)
        if not rules:
            print(" please add setup.xlsx with columns: start, end, phrase")
            raise SystemExit

        email_lines = email_loading(EMAIL_FILE)
        if not email_lines:
            print("No email")
            raise SystemExit

        start_tag = rules[0]["start"]
        end_tag = rules[0]["end"]

        start_line, segment_text = segment_Extraction(email_lines, start_tag, end_tag)
        if start_line == 0 or not segment_text.strip():
            print("THere is no segment between", repr(start_tag), "and", repr(end_tag))
            print("*** Full email preview (first 200 chars) ***")
            preview = "".join(email_lines)[:200]
            print(preview)
            raise SystemExit

        print(f"🔎 Segment extracted starting at line {start_line}. Preview (first 300 chars):")
        print(segment_text[:300].replace("\n", " "))

        suspicious = phishingParts_checking(segment_text, rules)

        if suspicious:
            suspicious = sorted(list(set(suspicious)))
            print("\n Suspicious phrases FOUND:")
            for p in suspicious:
                print("   -", p)
            print(f"\nResult: FAIL — {len(suspicious)} suspicious phrase(s) found in <body> starting at line {start_line}.")

            # store result in MongoDB
            collection.insert_one({
                "file": EMAIL_FILE,
                "result": "FAIL",
                "found_phrases": suspicious,
                "start_line": start_line,
                "timestamp": datetime.now()
            })
        else:
            print(" No suspicious phrases found in the <body>. Result: PASS")

            # store result in MongoDB
            collection.insert_one({
                "file": EMAIL_FILE,
                "result": "PASS",
                "found_phrases": [],
                "start_line": start_line,
                "timestamp": datetime.now()
            })

    except Exception as e:
        print("Unexpected error:", e)
