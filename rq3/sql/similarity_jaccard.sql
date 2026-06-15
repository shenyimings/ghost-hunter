WITH
ref_compilations AS (
  SELECT DISTINCT vc.compilation_id
  FROM `<YOUR_PROJECT_ID>.sourcify_dataset.public_contract_deployments` cd
  JOIN `<YOUR_PROJECT_ID>.sourcify_dataset.public_verified_contracts` vc
    ON vc.deployment_id = cd.id
  WHERE cd.chain_id = 137
    AND cd.address IN (
      FROM_HEX('4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e'),  -- CTFExchange
      FROM_HEX('c5d563a36ae78145c45a50134d48a1215220f80a'),  -- NegRiskCtfExchange
      FROM_HEX('56c79347e95530c01a2fc76e732f9566da16e113'),  -- FeeModule
      FROM_HEX('b768891e3130f6df18214ac804d4db76c2c37730')   -- NegRiskFeeModule V2
    )
),
ref_sigs AS (
  SELECT DISTINCT rc.compilation_id AS ref_id, ccs.signature_hash_32
  FROM ref_compilations rc
  JOIN `<YOUR_PROJECT_ID>.sourcify_dataset.public_compiled_contracts_signatures` ccs
    ON ccs.compilation_id = rc.compilation_id
  WHERE ccs.signature_type = 'function'
),
ref_card AS (SELECT ref_id, COUNT(*) AS n_ref FROM ref_sigs GROUP BY ref_id),

inter AS (
  SELECT ccs.compilation_id AS cid, rs.ref_id,
         COUNT(DISTINCT ccs.signature_hash_32) AS n_inter
  FROM `<YOUR_PROJECT_ID>.sourcify_dataset.public_compiled_contracts_signatures` ccs
  JOIN ref_sigs rs USING (signature_hash_32)
  WHERE ccs.signature_type = 'function'
  GROUP BY cid, rs.ref_id
),

cand_card AS (
  SELECT ccs.compilation_id AS cid, COUNT(DISTINCT ccs.signature_hash_32) AS n_cand
  FROM `<YOUR_PROJECT_ID>.sourcify_dataset.public_compiled_contracts_signatures` ccs
  WHERE ccs.signature_type = 'function'
    AND ccs.compilation_id IN (SELECT DISTINCT cid FROM inter)
  GROUP BY cid
),

jaccard AS (
  SELECT i.cid,
         MAX(SAFE_DIVIDE(i.n_inter, cc.n_cand + rcd.n_ref - i.n_inter)) AS max_jaccard,
         MAX(i.n_inter) AS best_overlap_count
  FROM inter i
  JOIN cand_card cc ON cc.cid = i.cid
  JOIN ref_card  rcd ON rcd.ref_id = i.ref_id
  GROUP BY i.cid
)
SELECT
  cd.chain_id,
  CONCAT('0x', LOWER(TO_HEX(cd.address))) AS address,
  cc.name AS contract_name,
  cc.fully_qualified_name,
  ROUND(j.max_jaccard, 4) AS max_jaccard,
  j.best_overlap_count,
  vc.created_at AS verified_at
FROM jaccard j
JOIN `<YOUR_PROJECT_ID>.sourcify_dataset.public_verified_contracts` vc
  ON vc.compilation_id = j.cid
JOIN `<YOUR_PROJECT_ID>.sourcify_dataset.public_contract_deployments` cd
  ON cd.id = vc.deployment_id
JOIN `<YOUR_PROJECT_ID>.sourcify_dataset.public_compiled_contracts` cc
  ON cc.id = j.cid
WHERE j.max_jaccard >= 0.10
ORDER BY max_jaccard DESC;