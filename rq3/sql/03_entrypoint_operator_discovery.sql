WITH t AS (SELECT 0xd0a08e8c493f9c94f29311604c9de1b4e8c8d4c06bd0c789af57f2d65bfec0f6 AS topic)
SELECT tx_to AS entrypoint, tx_from AS operator, count(distinct tx_hash) txs
FROM bnb.logs, t
WHERE topic0=topic
  AND contract_address=0x8a289d458f5a134ba40015085a8f50ffb681b41d
  AND block_date >= date '2026-05-06' AND block_date < date '2026-05-13'
GROUP BY 1,2
ORDER BY 3 DESC
