import pandas as pd

from core.preprocessing.uri_feature_extractor import extract_features, extract_domain_features, canonicalize_domain
from sklearn.model_selection import train_test_split

def uri_data_preprocessing():

    stealthPhisher = pd.read_csv("datasets/StealthPhisher2025.csv")
    stealthPhisher_urls = stealthPhisher["URL"].head(30000).apply(canonicalize_domain)
    stealthPhisher_labels = stealthPhisher["Label"].head(30000)
    stealthPhisher_labels = stealthPhisher_labels.map({"Legitimate": 0, "Phishing": 1})
    df_stealth = pd.DataFrame({
        "domain": stealthPhisher_urls,
        "label": stealthPhisher_labels
    })

    phish = pd.read_csv("datasets/phishtank_20122025.csv")
    phish_urls = phish["url"].dropna().unique()

    df_phish = pd.DataFrame({
        "domain": phish_urls,
        "label": 1
    })

    tranco = pd.read_csv("datasets/tranco_20122025.csv", header=None)
    domains = tranco[1].head(30000)

    benign_urls = ["http://" + d for d in domains]

    df_tranco = pd.DataFrame({
        "domain": benign_urls,
        "label": 0
    })

    def normalize(url):
        return url.strip().lower()

    df_phish["domain"] = df_phish["domain"].apply(normalize)
    df_tranco["domain"] = df_tranco["domain"].apply(normalize)
    df_stealth["domain"] = df_stealth["domain"].apply(normalize)


    df = pd.concat([df_phish, df_tranco, df_stealth], ignore_index=True)
    df.drop_duplicates(subset="domain", inplace=True)
    df = df[df["domain"].str.len() > 10]

    df_mal = df[df["label"] == 1].sample(40000, random_state=42)
    df_ben = df[df["label"] == 0].sample(40000, random_state=42)

    final_df = pd.concat([df_mal, df_ben])
    final_df = final_df.sample(frac=1).reset_index(drop=True)
    final_df.to_csv("datasets/domains.csv", index=False)

    X = final_df["domain"].apply(extract_domain_features).apply(pd.Series)
    y = final_df["label"]

    X_train, X_val, y_train, y_val = train_test_split(
        X, y,
        test_size=0.2,
        stratify=y,
        random_state=42
    )
    
    return X_train, X_val, y_train, y_val

import pandas as pd

# def build_disjoint_eval_csv():

#     # ---------- Load existing dataset ----------
#     used_df = pd.read_csv("datasets/urls.csv")
#     used_urls = set(used_df["url"].str.lower().str.strip())

#     # ---------- Load raw sources ----------
#     phish = pd.read_csv("datasets/phishtank_20122025.csv")
#     phish_urls = (
#         phish["url"]
#         .dropna()
#         .str.lower()
#         .str.strip()
#         .unique()
#     )

#     tranco = pd.read_csv("datasets/tranco_20122025.csv", header=None)
#     benign_domains = tranco[1].str.lower().str.strip()
#     benign_urls = ["http://" + d for d in benign_domains]

#     # ---------- Remove used URLs ----------
#     phish_urls = [u for u in phish_urls if u not in used_urls]
#     benign_urls = [u for u in benign_urls if u not in used_urls]

#     # ---------- Build dataframes ----------
#     df_phish = pd.DataFrame({"url": phish_urls, "label": 1})
#     df_benign = pd.DataFrame({"url": benign_urls, "label": 0})

#     df_phish = df_phish[df_phish["url"].str.len() > 10]
#     df_benign = df_benign[df_benign["url"].str.len() > 10]

#     # ---------- Sample SAME SIZE ----------
#     n_phish = len(df_phish)
#     n_benign = len(df_benign)
#     n = min(n_phish, n_benign)

#     print(f"Building eval set with {n} malicious + {n} benign URLs")

#     df_phish = df_phish.sample(n, random_state=1337)
#     df_benign = df_benign.sample(n, random_state=1337)

#     final_df = pd.concat([df_phish, df_benign])
#     final_df = final_df.sample(frac=1, random_state=1337).reset_index(drop=True)

#     # ---------- Final safety check ----------
#     assert set(final_df["url"]).isdisjoint(used_urls), "URL leakage detected!"

#     final_df.to_csv("datasets/urls_eval.csv", index=False)

#     print("Evaluation CSV created:", final_df.shape)
#     X = final_df["url"].apply(extract_features).apply(pd.Series)
#     y = final_df["label"]

#     return X, y

