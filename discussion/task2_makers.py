import pandas as pd, json
BASE='../results'

rows=[]
for f,vol in [('all_v1.parquet','v1'),('all_v2.parquet','v2')]:
    df=pd.read_parquet(f'{BASE}/{f}',columns=['affected_amount','timestamp','matched_rule','rule_result'])
    df=df[df['matched_rule']=='proxy_trap'].copy()
    df['version']=vol
    rows.append(df)
df=pd.concat(rows,ignore_index=True)
print('total proxy_trap rows:',len(df))

def parse(s):
    try:
        d=json.loads(s); return d.get('proxy_trap_side'),(d.get('trapped_address') or '').lower(),(d.get('attacker') or '').lower()
    except: return None,'',''
df[['side','trapped','attacker']]=df['rule_result'].apply(lambda s:pd.Series(parse(s)))
print(df['side'].value_counts(dropna=False))

maker=df[df['side']=='maker'].copy()
print('maker-side proxy_trap rows:',len(maker))
maker['ts']=pd.to_datetime(maker['timestamp'],errors='coerce',utc=True)
g=maker.groupby('trapped').agg(count=('trapped','size'),affected=('affected_amount','sum'),
    first=('ts','min'),last=('ts','max'),
    attackers=('attacker',lambda x:x.nunique()),
    versions=('version',lambda x:','.join(sorted(set(x))))).reset_index()
g=g.sort_values('count',ascending=False).head(25).reset_index(drop=True)
pd.set_option('display.width',200,'display.max_colwidth',50)
for i,r in g.iterrows():
    print(f"{i+1:2d} {r['trapped']} cnt={r['count']:5d} aff=${r['affected']:>12,.0f} nattk={r['attackers']:3d} {r['versions']:5s} {str(r['first'])[:10]}..{str(r['last'])[:10]}")
g.to_csv('proxy_trap_makers.csv',index=False)
