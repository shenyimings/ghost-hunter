WITH t AS (SELECT 0xd0a08e8c493f9c94f29311604c9de1b4e8c8d4c06bd0c789af57f2d65bfec0f6 AS topic)
SELECT contract_address, count(*) n, min(block_date) first_day, max(block_date) last_day
FROM opbnb.logs, t
WHERE topic0=topic
GROUP BY 1
ORDER BY 2 DESC
