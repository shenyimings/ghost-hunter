SELECT block_date,
       count(*) matchorders_tx,
       count_if(NOT success) reverted,
       round(100.0*count_if(NOT success)/count(*),3) revert_pct
FROM base.transactions
WHERE "to" = 0xf94ef760884b0605e433853aed17da574160226e
  AND bytearray_substring(data,1,4) = 0xd2539b37
  AND block_date < date '2026-06-13'
GROUP BY 1
HAVING count(*) >= 200
ORDER BY revert_pct DESC
LIMIT 20
