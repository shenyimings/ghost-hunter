SELECT block_date,
       count(*) matchorders_tx,
       count_if(NOT success) reverted,
       round(100.0*count_if(NOT success)/count(*),3) revert_pct
FROM bnb.transactions
WHERE block_date >= date '2026-05-06' AND block_date < date '2026-05-13'
  AND "to" = 0xd172f3fbabe763ee8e52d8b32421574236da6057
  AND bytearray_substring(data,1,4) = 0x2287e350
GROUP BY 1
ORDER BY 1
