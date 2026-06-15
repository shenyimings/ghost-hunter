import requests,time,json
from collections import Counter

def get(url,**kw):
    for _ in range(5):
        try:
            r=requests.get(url,timeout=25,**kw)
            return r
        except Exception:
            time.sleep(2)
    return None

cases={'maker1_db74':'0xdb7428c3c0a198caef35e0543318c105be8acffe',
'maker2_4b53':'0x4b53251298b722afbca3908b93fe7a78503b5969',
'maker3_34b1':'0x34b1cec3c0373d1d910e68478f3edcc834d93f21',
'maker4_bf58':'0xbf586f0de884ce274327e7c61706cada2ece59cb',
'maker5_0cbe':'0x0cbe637030a627b0342bf06c75430927aa42a6f0'}

out={}
for name,addr in cases.items():
    acts=[]
    off=0
    while True:
        r=get('https://data-api.polymarket.com/activity',params={'user':addr,'limit':500,'offset':off})
        if not r or r.status_code!=200: break
        j=r.json()
        if not j: break
        acts+=j
        off+=500
        if len(j)<500: break
        if off>5000: break
    types=Counter(a['type'] for a in acts)
    titles=Counter(a.get('title','') for a in acts)
    trade_vol=sum(a.get('usdcSize',0) for a in acts if a['type']=='TRADE')
    redeem_vol=sum(a.get('usdcSize',0) for a in acts if a['type']=='REDEEM')
    btc5m=sum(1 for a in acts if 'Up or Down' in a.get('title',''))
    out[name]={'addr':addr,'n_activity':len(acts),'types':dict(types),
               'trade_usdc':round(trade_vol,2),'redeem_usdc':round(redeem_vol,2),
               'btc5m_share':f'{btc5m}/{len(acts)}','top_titles':titles.most_common(3)}
    print(name,addr)
    print('  ',out[name])
json.dump(out,open('activity_summary.json','w'),indent=2)
