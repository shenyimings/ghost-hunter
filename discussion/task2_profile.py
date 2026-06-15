import pandas as pd, json
BASE='../results'

df=pd.read_parquet(f'{BASE}/all_v2.parquet')
df=df[df['matched_rule']=='proxy_trap'].copy()
def parse(s):
    try:
        d=json.loads(s);return d.get('proxy_trap_side'),(d.get('trapped_address')or'').lower(),(d.get('attacker')or'').lower()
    except:return None,'',''
df[['side','trapped','attacker']]=df['rule_result'].apply(lambda s:pd.Series(parse(s)))
df['ts']=pd.to_datetime(df['timestamp'],errors='coerce',utc=True)

cases=['0xdb7428c3c0a198caef35e0543318c105be8acffe',
'0x4b53251298b722afbca3908b93fe7a78503b5969',
'0x34b1cec3c0373d1d910e68478f3edcc834d93f21',
'0xbf586f0de884ce274327e7c61706cada2ece59cb',
'0x0cbe637030a627b0342bf06c75430927aa42a6f0']
for c in cases:
    sub=df[(df['side']=='maker')&(df['trapped']==c)]
    print('\n=== maker',c,'reverts=',len(sub))
    print('  span',str(sub['ts'].min()),'->',str(sub['ts'].max()))
    print('  attacker(companion) addrs:',sub['attacker'].value_counts().head(3).to_dict())
    print('  distinct condition_ids:',sub['condition_id'].nunique())
    print('  affected sum $%.0f'%sub['affected_amount'].sum())
    hr=sub['ts'].dt.hour.value_counts().sort_index()
    print('  hour-of-day spread (UTC):',dict(hr))
