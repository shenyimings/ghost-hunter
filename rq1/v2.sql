SELECT
  b.block_number,
  r.to_address                                                   AS contract_address,
  t.transaction_hash,
  t.block_timestamp,
  t.transaction_index,
  t.input                                                        AS tx_input,
  r.gas_used,
  r.effective_gas_price,
  CAST(r.gas_used AS BIGNUMERIC)
    * CAST(r.effective_gas_price AS BIGNUMERIC)                  AS gas_fee_wei,
FROM `bigquery-public-data.goog_blockchain_polygon_mainnet_us.receipts`     AS r
JOIN `bigquery-public-data.goog_blockchain_polygon_mainnet_us.transactions` AS t
  ON r.transaction_hash = t.transaction_hash
JOIN `bigquery-public-data.goog_blockchain_polygon_mainnet_us.blocks`       AS b
  ON r.block_hash = b.block_hash
WHERE r.block_timestamp >= TIMESTAMP('2026-04-28 00:00:00+00')
  AND r.block_timestamp <  TIMESTAMP('2026-05-06 00:00:00+00')
  AND t.block_timestamp >= TIMESTAMP('2026-04-28 00:00:00+00')
  AND t.block_timestamp <  TIMESTAMP('2026-05-06 00:00:00+00')
  AND b.block_timestamp >= TIMESTAMP('2026-04-28 00:00:00+00')
  AND b.block_timestamp <  TIMESTAMP('2026-05-06 00:00:00+00')
  AND r.to_address IN (
        '0xe111180000d2663c0091e4f400237545b87b996b',  -- CTF Exchange V2
        '0xe2222d279d744050d28e00520010520000310f59'   -- Negrisk V2
      )
  AND r.status = 0
  AND STARTS_WITH(t.input, '0x3c2b4399')
ORDER BY r.to_address, b.block_number, t.transaction_index;