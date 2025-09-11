import pandas as pd;


def loading_rules(file_path):
    df = pd.read_excel(file_path)
    rules =[]
    for _, row in df.iterrows():
        rules.append({
            "start": str(row["start"]),
            "end": str(row["end"]),
            "phrase": str(row["phrase"]).lower()
        })

    return rules


def loading_email(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        return f.readline()