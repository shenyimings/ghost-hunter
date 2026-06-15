WITH t AS (SELECT 0xd0a08e8c493f9c94f29311604c9de1b4e8c8d4c06bd0c789af57f2d65bfec0f6 AS topic),
safes AS (
  SELECT DISTINCT tx_to AS safe
  FROM bnb.logs, t
  WHERE topic0=topic AND contract_address=0x5f45344126d6488025b0b84a3a8189f2487a7246
    AND block_date >= date '2026-04-12' AND block_date < date '2026-06-13'
)
SELECT l.block_date,
  count_if(l.topic0 = 0x442e715f626346e8c54381002da614f62bee8d27386535b2521ec8540898556e) AS success,
  count_if(l.topic0 = 0x23428b18acfb3ea64b08dc0c1d296ea9c09702c09083ca5272e64d115b687d23) AS failure,
  round(100.0*count_if(l.topic0 = 0x23428b18acfb3ea64b08dc0c1d296ea9c09702c09083ca5272e64d115b687d23)
        /nullif(count_if(l.topic0 IN (0x442e715f626346e8c54381002da614f62bee8d27386535b2521ec8540898556e,
                                      0x23428b18acfb3ea64b08dc0c1d296ea9c09702c09083ca5272e64d115b687d23)),0),3) AS failure_pct
FROM bnb.logs l
JOIN safes s ON l.contract_address = s.safe
WHERE l.block_date >= date '2026-04-12' AND l.block_date < date '2026-06-13'
  AND l.topic0 IN (0x442e715f626346e8c54381002da614f62bee8d27386535b2521ec8540898556e,
                   0x23428b18acfb3ea64b08dc0c1d296ea9c09702c09083ca5272e64d115b687d23)
GROUP BY 1
ORDER BY failure_pct DESC
LIMIT 20
