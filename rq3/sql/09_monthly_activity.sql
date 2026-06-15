WITH t AS (SELECT 0xd0a08e8c493f9c94f29311604c9de1b4e8c8d4c06bd0c789af57f2d65bfec0f6 AS topic)
SELECT date_trunc('month', block_date) mth,
       count(*) orderfilled,
       count(distinct tx_hash) txs,
       count(distinct tx_to) entrypoints,
       count(distinct tx_from) operators
FROM bnb.logs, t
WHERE topic0=topic AND contract_address=0xf99f5367ce708c66f0860b77b4331301a5597c86
GROUP BY 1
ORDER BY 1
