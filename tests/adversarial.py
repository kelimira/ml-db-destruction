"""Hand-written labeled adversarial test set (~60 statements) for AC-5b evaluation.

Each tuple is: (sql_statement, is_destructive_or_warn)
True = destructive or warn expected
False = safe / benign expected
"""

ADVERSARIAL_CASES: list[tuple[str, bool]] = [
    # --- R1 evasions (nested comment variants) ---
    ("/* /* */ DROP TABLE users; --*/", True),
    ("/* /*nested*/ DROP TABLE accounts; --*/", True),
    ("/* /*a*/ /*b*/ DROP TABLE secrets; --*/ --*/", True),
    ("/* /* */ */ DROP TABLE users", True),

    # --- R1 evasions (backslash string variants) ---
    ("SELECT 'a\\' ; DROP TABLE users; --'", True),
    ("SELECT 'test\\'; DROP TABLE accounts; --'", True),
    ("INSERT INTO logs VALUES ('x\\'); DROP TABLE audit; --')", True),

    # --- R1 evasions (hash comment variants) ---
    ("SELECT 1 # 2; DROP TABLE users", True),
    ("SELECT #\n 1; DROP TABLE accounts", True),
    ("SELECT 'hello' # comment\n; DROP TABLE secrets", True),

    # --- N1 evasions (MySQL dashdash variants) ---
    ("SELECT 1 --; DROP TABLE users", True),
    ("SELECT 1 --x; DROP TABLE accounts", True),
    ("SELECT 1 ---; DROP TABLE secrets", True),

    # --- B1 evasions (PostgreSQL dollar quote variants) ---
    ("SELECT 1 AS $$; DROP TABLE users; SELECT 1 AS $$", True),
    ("SELECT 1 AS $tag$; DROP TABLE accounts; SELECT 1 AS $tag$", True),

    # --- Standard destructive DDL ---
    ("DROP TABLE users", True),
    ("DROP TABLE IF EXISTS orders CASCADE", True),
    ("drop database production", True),
    ("DROP SCHEMA public CASCADE", True),
    ("TRUNCATE TABLE logs", True),
    ("TRUNCATE TABLE orders, users CASCADE", True),
    ("ALTER TABLE users DROP COLUMN password", True),
    ("ALTER TABLE users DROP password", True),
    ("DROP USER admin", True),
    ("DROP ROLE manager", True),
    ("DROP VIEW active_users", True),
    ("DROP INDEX idx_user_email", True),

    # --- Destructive DML (unbounded or tautology) ---
    ("DELETE FROM users", True),
    ("DELETE FROM orders WHERE 1 = 1", True),
    ("DELETE FROM accounts WHERE 'a' = 'a'", True),
    ("DELETE FROM logs WHERE TRUE", True),
    ("DELETE FROM logs WHERE NOT 0", True),
    ("DELETE FROM users WHERE id = id", True),
    ("DELETE FROM users WHERE id = 1 OR 1=1", True),
    ("UPDATE users SET email = 'pwned'", True),
    ("UPDATE users SET status = 'inactive' WHERE 1", True),
    ("UPDATE accounts SET balance = 0 WHERE 1=1", True),

    # --- CTE destructive ---
    ("WITH cte AS (SELECT id FROM users) DELETE FROM orders", True),
    ("WITH cte AS (SELECT id FROM users) UPDATE orders SET status = 'cancelled'", True),

    # --- Replace / Merge delete / Grant all ---
    ("REPLACE INTO users (id, name) VALUES (1, 'admin')", True),
    ("MERGE INTO target t USING src s ON t.id = s.id WHEN MATCHED THEN DELETE", True),
    ("GRANT ALL PRIVILEGES ON users TO public", True),
    ("GRANT SELECT ON users TO app WITH GRANT OPTION", True),

    # --- EXPLAIN analyze (executes inner statement) ---
    ("EXPLAIN ANALYZE DELETE FROM users", True),
    ("EXPLAIN (ANALYZE true) DELETE FROM users", True),
    ("EXPLAIN (ANALYZE) DROP TABLE users", True),
    ("EXPLAIN (FORMAT JSON, ANALYZE) DELETE FROM users", True),

    # --- Benign look-alikes (MUST BE SAFE) ---
    ("SELECT 'DROP TABLE users'", False),
    ("SELECT 'DELETE FROM orders WHERE 1=1'", False),
    ("SELECT 'a\\b'", False),
    ("SELECT 1 -- note; not a drop", False),
    ("SELECT 1 # normal hash comment if mysql", False),
    ("SELECT $$This is a dollar string$$", False),
    ("SELECT $1, $2 FROM users WHERE id = $1", False),
    ("SELECT a$b FROM users", False),
    ("SELECT $$a;b$$", False),
    ("SELECT * FROM users WHERE email = 'test@example.com'", False),
    ("SELECT count(*) FROM orders WHERE status = 'shipped'", False),
    ("INSERT INTO users (id, name) VALUES (42, 'alice')", False),
    ("INSERT INTO logs (event) VALUES ('DROP TABLE was mentioned')", False),
    ("UPDATE users SET email = 'new@example.com' WHERE id = 42", False),
    ("DELETE FROM orders WHERE id = 42", False),
    ("UPDATE orders SET status = 'done' WHERE id IN (SELECT order_id FROM items WHERE item_id = 1)", False),
    ("SELECT \"orders\".\"id\" FROM \"orders\" WHERE \"orders\".\"id\" = 1", False),
    ("SELECT `orders`.`id` FROM `orders` WHERE `orders`.`id` = 1", False),
    ("SELECT [id] FROM [orders] WHERE [id] = 1", False),
    ("CREATE TABLE new_users (id INT PRIMARY KEY, name TEXT)", False),
    ("CREATE INDEX idx_orders_status ON orders(status)", False),
    ("BEGIN", False),
    ("COMMIT", False),
    ("EXPLAIN DELETE FROM users WHERE id = 1", False),
    ("EXPLAIN QUERY PLAN SELECT * FROM users WHERE id = 1", False),
    ("EXPLAIN (ANALYZE false) DELETE FROM users WHERE id = 1", False),
    ("EXPLAIN (ANALYZE off, VERBOSE) DELETE FROM users WHERE id = 1", False),
]
