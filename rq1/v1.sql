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
WHERE r.block_timestamp >= TIMESTAMP('2025-08-15 00:00:00+00')
  AND r.block_timestamp <  TIMESTAMP('2026-04-28 00:00:00+00')
  AND t.block_timestamp >= TIMESTAMP('2025-08-15 00:00:00+00')
  AND t.block_timestamp <  TIMESTAMP('2026-04-28 00:00:00+00')
  AND b.block_timestamp >= TIMESTAMP('2025-08-15 00:00:00+00')
  AND b.block_timestamp <  TIMESTAMP('2026-04-28 00:00:00+00')
  AND r.to_address IN (
        '0xb768891e3130f6df18214ac804d4db76c2c37730',  -- neg_risk_fee_module (V1)
        '0xe3f18acc55091e2c48d883fc8c8413319d4ab7b0'   -- ctf_exchange_fee_module (V1)
      )
  AND r.status = 0
  AND STARTS_WITH(t.input, '0x2287e350')
ORDER BY r.to_address, b.block_number, t.transaction_index;