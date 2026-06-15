WITH t AS (SELECT 0xd0a08e8c493f9c94f29311604c9de1b4e8c8d4c06bd0c789af57f2d65bfec0f6 AS topic)
SELECT 'optimism' c, count(*) n, count(distinct contract_address) nc FROM optimism.logs, t WHERE topic0=topic
UNION ALL SELECT 'opbnb', count(*), count(distinct contract_address) FROM opbnb.logs, t WHERE topic0=topic
UNION ALL SELECT 'cronos', count(*), count(distinct contract_address) FROM cronos.logs, t WHERE topic0=topic
UNION ALL SELECT 'sei', count(*), count(distinct contract_address) FROM sei.logs, t WHERE topic0=topic
ORDER BY 2 DESC
