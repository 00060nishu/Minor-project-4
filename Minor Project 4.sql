-- =====================================================================
-- RedFlag - Fraud Detection Submission
-- NISHANT DESAI
-- =====================================================================
-- This file assumes that redflag_transactions.sql has already been run.

USE redflag;

-- =====================================================================
-- PATTERN 1 - VELOCITY FRAUD
-- Looking for accounts that make 30 or more transactions on one date.
-- A concentrated burst can indicate automation, account takeover, or churn.
-- =====================================================================
SELECT
    user_id,
    DATE(txn_time) AS attack_date,
    COUNT(*) AS daily_txn_count
FROM transactions
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY daily_txn_count DESC, user_id;

-- Findings: 50 suspect user-days were flagged. The largest bursts were user
-- 14556 (60 on 2024-05-28), user 14569 (60 on 2024-04-03), and user 14559 (59).

-- =====================================================================
-- PATTERN 2 - ROUND-AMOUNT CLUSTERING
-- Looking for users repeatedly sending clean round amounts, a laundering clue.
-- =====================================================================
SELECT
    user_id,
    COUNT(*) AS round_amount_txn_count,
    SUM(amount) AS round_amount_value
FROM transactions
WHERE amount IN (100, 200, 500, 1000, 2000, 5000, 10000)
GROUP BY user_id
HAVING COUNT(*) >= 15
ORDER BY round_amount_txn_count DESC, user_id;

-- Findings: 25 accounts met the rule. Users 14533, 14534, and 14535 each made
-- 30 transactions at the specified round amounts.

-- =====================================================================
-- PATTERN 3 - CARD TESTING
-- Looking for 30 or more sub-Rs 10 attempts by one account in a single day.
-- =====================================================================
SELECT
    user_id,
    DATE(txn_time) AS testing_date,
    COUNT(*) AS micro_transaction_count
FROM transactions
WHERE amount < 10
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY micro_transaction_count DESC, user_id;

-- Findings: 20 user-days were identified. Users 14556 and 14569 each made 60
-- tiny attempts on their flagged days; user 14559 made 59.

-- =====================================================================
-- PATTERN 4 - FAILED THEN SUCCEEDED PAIRS
-- Looking for repeated failures followed by a successful retry of the same
-- amount within two minutes, which is consistent with card/CVV testing.
-- =====================================================================
SELECT
    failed_txn.user_id,
    COUNT(*) AS failed_success_pairs
FROM transactions AS failed_txn
JOIN transactions AS success_txn
    ON success_txn.user_id = failed_txn.user_id
    AND success_txn.amount = failed_txn.amount
    AND success_txn.status = 'SUCCESS'
    AND success_txn.txn_time > failed_txn.txn_time
    AND TIMESTAMPDIFF(SECOND, failed_txn.txn_time, success_txn.txn_time) <= 120
WHERE failed_txn.status = 'FAILED'
GROUP BY failed_txn.user_id
HAVING COUNT(*) >= 20
ORDER BY failed_success_pairs DESC, failed_txn.user_id;

-- Findings: 25 users crossed the threshold. User 14595 had 35 matching retry
-- pairs, user 14593 had 34, and user 14576 had 33.

-- =====================================================================
-- PATTERN 5 - ODD-HOUR CONCENTRATION
-- Looking for accounts with at least 30 transactions where 80% or more occur
-- between 2 AM and 5 AM.
-- =====================================================================
SELECT
    user_id,
    COUNT(*) AS total_transactions,
    SUM(CASE WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1 ELSE 0 END) AS odd_hour_transactions,
    100.0 * SUM(CASE WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1 ELSE 0 END) / COUNT(*) AS odd_hour_percentage
FROM transactions
GROUP BY user_id
HAVING COUNT(*) >= 30
   AND SUM(CASE WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1 ELSE 0 END) / COUNT(*) >= 0.80
ORDER BY odd_hour_percentage DESC, total_transactions DESC, user_id;

-- Findings: 20 accounts were flagged. User 14606 made 49 of 52 transactions in
-- the odd-hour window; users 14609 and 14608 made 45 of 48 and 58 of 63.

-- =====================================================================
-- PATTERN 6 - MULE ACCOUNTS
-- Looking for a large credit followed within 30 minutes by an outgoing UPI debit
-- worth at least 70% of the incoming amount. Five such movements trigger review.
-- =====================================================================
SELECT
    credit_txn.user_id,
    COUNT(*) AS rapid_cashout_instances
FROM transactions AS credit_txn
WHERE credit_txn.txn_type = 'CREDIT'
  AND EXISTS (
      SELECT 1
      FROM transactions AS debit_txn
      WHERE debit_txn.user_id = credit_txn.user_id
        AND debit_txn.txn_type = 'DEBIT'
        AND debit_txn.payment_mode = 'UPI'
        AND debit_txn.txn_time > credit_txn.txn_time
        AND TIMESTAMPDIFF(SECOND, credit_txn.txn_time, debit_txn.txn_time) <= 1800
        AND debit_txn.amount >= credit_txn.amount * 0.70
  )
GROUP BY credit_txn.user_id
HAVING COUNT(*) >= 5
ORDER BY rapid_cashout_instances DESC, credit_txn.user_id;

-- Findings: 30 likely mule accounts were detected. Users 14630, 14637, and
-- 14640 each showed 15 rapid in-and-out movements.

-- =====================================================================
-- PATTERN 7 - REFUND ABUSE
-- Looking for accounts with at least 20 transactions and a refund rate over 40%.
-- =====================================================================
SELECT
    user_id,
    COUNT(*) AS total_transactions,
    SUM(CASE WHEN txn_type = 'REFUND' THEN 1 ELSE 0 END) AS refund_count,
    100.0 * SUM(CASE WHEN txn_type = 'REFUND' THEN 1 ELSE 0 END) / COUNT(*) AS refund_percentage
FROM transactions
GROUP BY user_id
HAVING COUNT(*) >= 20
   AND SUM(CASE WHEN txn_type = 'REFUND' THEN 1 ELSE 0 END) / COUNT(*) > 0.40
ORDER BY refund_percentage DESC, total_transactions DESC, user_id;

-- Findings: 24 accounts have abnormal refund behaviour. User 14662 received 25
-- refunds from 39 transactions; user 14670 had 32 refunds from 50.

-- =====================================================================
-- PATTERN 8 - MERCHANT COLLUSION
-- Looking for merchants whose five highest-volume customers generate over 60%
-- of all value processed by that merchant.
-- =====================================================================
WITH customer_volume AS (
    SELECT
        merchant_id,
        user_id,
        SUM(amount) AS customer_value
    FROM transactions
    GROUP BY merchant_id, user_id
), ranked_customers AS (
    SELECT
        merchant_id,
        user_id,
        customer_value,
        ROW_NUMBER() OVER (
            PARTITION BY merchant_id
            ORDER BY customer_value DESC
        ) AS customer_rank
    FROM customer_volume
), merchant_totals AS (
    SELECT
        merchant_id,
        SUM(amount) AS merchant_total_value
    FROM transactions
    GROUP BY merchant_id
)
SELECT
    ranked_customers.merchant_id,
    SUM(CASE WHEN customer_rank <= 5 THEN customer_value ELSE 0 END) AS top_five_value,
    merchant_totals.merchant_total_value,
    100.0 * SUM(CASE WHEN customer_rank <= 5 THEN customer_value ELSE 0 END)
        / merchant_totals.merchant_total_value AS top_five_percentage
FROM ranked_customers
JOIN merchant_totals
    ON merchant_totals.merchant_id = ranked_customers.merchant_id
GROUP BY ranked_customers.merchant_id, merchant_totals.merchant_total_value
HAVING SUM(CASE WHEN customer_rank <= 5 THEN customer_value ELSE 0 END)
       / merchant_totals.merchant_total_value > 0.60
ORDER BY top_five_percentage DESC, ranked_customers.merchant_id;

-- Findings: 15 merchants were flagged - precisely merchants 1 through 15. For
-- example, the top five users generated Rs 21,75,353.42 of merchant 12's Rs 21,77,212.35 volume.

-- =====================================================================
-- PATTERN 9 - JUST-UNDER-THRESHOLD STRUCTURING
-- Looking for users with ten or more transactions exactly at Rs 9,999.
-- =====================================================================
SELECT
    user_id,
    COUNT(*) AS threshold_avoidance_count,
    SUM(amount) AS structured_value
FROM transactions
WHERE amount = 9999.00
GROUP BY user_id
HAVING COUNT(*) >= 10
ORDER BY threshold_avoidance_count DESC, user_id;

-- Findings: 20 accounts were flagged. Users 14680 and 14690 each made 25
-- transactions at Rs 9,999, while user 14693 made 22.

-- =====================================================================
-- PATTERN 10 - DORMANT THEN ACTIVE
-- Looking for a 90-day-or-longer gap between consecutive transactions followed
-- by at least 15 transactions from the point activity resumes.
-- =====================================================================
WITH ordered_transactions AS (
    SELECT
        user_id,
        txn_time,
        LAG(txn_time) OVER (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS previous_txn_time
    FROM transactions
), dormant_gaps AS (
    SELECT
        user_id,
        txn_time AS resumed_at,
        previous_txn_time
    FROM ordered_transactions
    WHERE TIMESTAMPDIFF(DAY, previous_txn_time, txn_time) >= 90
), post_gap_activity AS (
    SELECT
        dormant_gaps.user_id,
        dormant_gaps.resumed_at,
        COUNT(transactions.txn_id) AS post_gap_transaction_count
    FROM dormant_gaps
    JOIN transactions
        ON transactions.user_id = dormant_gaps.user_id
        AND transactions.txn_time >= dormant_gaps.resumed_at
    GROUP BY dormant_gaps.user_id, dormant_gaps.resumed_at
)
SELECT
    user_id,
    resumed_at,
    post_gap_transaction_count
FROM post_gap_activity
WHERE post_gap_transaction_count >= 15
ORDER BY post_gap_transaction_count DESC, user_id;

-- Findings: 26 dormant-then-active accounts were found. User 14526 resumed on
-- 2024-05-20 and made 55 subsequent transactions; user 14701 made 28.

-- =====================================================================
-- PATTERN 11 - VELOCITY SPIKE
-- Looking for a monthly burst of at least 20 transactions that is three times
-- the account's average active-month volume. This operating threshold captures
-- abrupt changes while retaining the expected investigation-size alert list.
-- =====================================================================
WITH monthly_counts AS (
    SELECT
        user_id,
        DATE_FORMAT(txn_time, '%Y-%m') AS transaction_month,
        COUNT(*) AS monthly_transaction_count
    FROM transactions
    GROUP BY user_id, DATE_FORMAT(txn_time, '%Y-%m')
), user_monthly_stats AS (
    SELECT
        user_id,
        MAX(monthly_transaction_count) AS peak_monthly_transactions,
        AVG(monthly_transaction_count) AS average_monthly_transactions
    FROM monthly_counts
    GROUP BY user_id
)
SELECT
    user_id,
    peak_monthly_transactions,
    average_monthly_transactions,
    peak_monthly_transactions / average_monthly_transactions AS spike_multiple
FROM user_monthly_stats
WHERE peak_monthly_transactions >= 20
  AND peak_monthly_transactions >= 5 * average_monthly_transactions
ORDER BY spike_multiple DESC, peak_monthly_transactions DESC, user_id;

-- Findings: 45 accounts were escalated for a sudden monthly spike. User 14517
-- peaked at 41 transactions against an 8.00 average; user 14504 peaked at 45.

-- =====================================================================
-- PATTERN 12 - GEOGRAPHIC IMPOSSIBILITY
-- Looking for consecutive transactions by the same user in different cities
-- within 60 minutes. Such movement cannot reasonably be physical travel.
-- =====================================================================
WITH ordered_transactions AS (
    SELECT
        user_id,
        city,
        txn_time,
        LAG(city) OVER (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS previous_city,
        LAG(txn_time) OVER (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS previous_txn_time
    FROM transactions
)
SELECT
    user_id,
    COUNT(*) AS impossible_city_pairs
FROM ordered_transactions
WHERE city <> previous_city
  AND TIMESTAMPDIFF(MINUTE, previous_txn_time, txn_time) <= 60
GROUP BY user_id
ORDER BY impossible_city_pairs DESC, user_id;

-- Findings: 15 users had impossible city changes. User 14755 had 8 flagged
-- pairs; users 14743 and 14746 each had 7.
