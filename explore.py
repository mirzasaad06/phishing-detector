import pandas as pd

df = pd.read_csv('dataset/phishing.csv')

print("Shape:", df.shape)
print("\nColumns:", df.columns.tolist())
print("\nFirst 3 rows:")
print(df.head(3))
print("\nLabel counts:")
print(df.iloc[:, -1].value_counts())