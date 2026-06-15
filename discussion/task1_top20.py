import pandas as pd, json
from collections import defaultdict

ATTACK_RULES = {'nonce_bump', 'balance_drain', 'balance_drain_normal_gas', 'approve_revoke', 'proxy_trap'}
def norm_vec(r):
    return 'balance_drain' if r == 'balance_drain_normal_gas' else r

frames = []
for f, vol in [('all_v1.parquet','v1'), ('all_v2.parquet','v2')]:
    df = pd.read_parquet(f'../results/{f}',
                         columns=['affected_amount','timestamp','matched_rule','rule_result'])
    df = df[df['matched_rule'].isin(ATTACK_RULES)].copy()
    df['version'] = vol
    frames.append(df)
df = pd.concat(frames, ignore_index=True)
print("total attack rows:", len(df))

# extract attacker
def get_attacker(s):
    try:
        d = json.loads(s)
        a = d.get('attacker', '') or d.get('cause_addr', '')
        return a.lower() if a else ''
    except Exception:
        return ''
df['attacker'] = df['rule_result'].map(get_attacker)
print("rows with attacker:", (df['attacker']!='').sum())

df = df[df['attacker'] != ''].copy()
df['vec'] = df['matched_rule'].map(norm_vec)
df['ts'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)

g = df.groupby('attacker')
res = g.agg(count=('attacker','size'),
            affected=('affected_amount','sum'),
            first=('ts','min'), last=('ts','max')).reset_index()
# dominant vector
dom = df.groupby(['attacker','vec']).size().reset_index(name='n')
dom = dom.sort_values('n', ascending=False).drop_duplicates('attacker').set_index('attacker')['vec']
res['dominant_vector'] = res['attacker'].map(dom)
res = res.sort_values('count', ascending=False).head(20).reset_index(drop=True)

lines = ["| Rank | Address | Attacks | Dominant Vector | Affected USD | First | Last |",
         "|---|---|---|---|---|---|---|"]
for i, row in res.iterrows():
    lines.append(f"| {i+1} | {row['attacker']} | {row['count']:,} | {row['dominant_vector']} | "
                 f"${row['affected']:,.0f} | {str(row['first'])[:10]} | {str(row['last'])[:10]} |")
table = "\n".join(lines)
md = "# Task 1: Top-20 Attacker Addresses (v1+v2 combined)\n\n" + table + "\n"
open('top20_attackers.md','w').write(md)
print(table)
