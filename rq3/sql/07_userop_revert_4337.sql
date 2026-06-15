SELECT block_date,
       count_if(topic0 = 0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f) AS total_userops,
       count_if(topic0 = 0x1c4fada7374c0a9ee8841fc38afe82932dc0f8e69012e927f061a8bae611a201) AS reverted_userops,
       round(100.0*count_if(topic0 = 0x1c4fada7374c0a9ee8841fc38afe82932dc0f8e69012e927f061a8bae611a201)
             /nullif(count_if(topic0 = 0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f),0),3) AS revert_pct
FROM bnb.logs
WHERE block_date >= date '2026-01-15' AND block_date < date '2026-01-22'
  AND contract_address = 0x0000000071727de22e5e9d8baf0edac6f37da032
  AND bytearray_substring(tx_from,1,2) = 0x4337
  AND topic0 IN (0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f,
                 0x1c4fada7374c0a9ee8841fc38afe82932dc0f8e69012e927f061a8bae611a201)
GROUP BY 1
ORDER BY 1
